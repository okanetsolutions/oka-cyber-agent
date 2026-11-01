// Package sqlite reads rows from SQLite 3 database files, for the dnf history database. Release builds have no
// cgo, and the pure Go SQLite drivers are far larger than reading a few tables needs, so this follows the documented
// file format (https://www.sqlite.org/fileformat2.html) instead.
//
// It is read only: it opens the database and its write-ahead log with O_RDONLY, never takes a lock and ignores the
// shared memory index. It applies the committed frames of the write-ahead log, as SQLite's own recovery does, so
// it sees transactions that were not checkpointed yet. It reads rowid tables with UTF-8 text only.
package sqlite

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"strings"
)

// ErrMalformed means the file is not a database this reader understands, or was changed while it was read.
var ErrMalformed = errors.New("malformed database")

const (
	headerMagic   = "SQLite format 3\x00"
	walMagicLE    = 0x377f0682
	walMagicBE    = 0x377f0683
	walVersion    = 3007000
	walHeaderSize = 32
	walFrameSize  = 24
	maxTreeDepth  = 32

	pageInteriorTable = 0x05
	pageLeafTable     = 0x0d
)

type DB struct {
	file     *os.File
	wal      *os.File
	pageSize int
	usable   int
	pages    uint32
	// walPages maps a page number to the offset of its latest committed copy in the write-ahead log.
	walPages map[uint32]int64
}

func Open(path string) (*DB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	db, err := open(file, path)
	if err != nil {
		file.Close()
		return nil, err
	}
	return db, nil
}

func open(file *os.File, path string) (*DB, error) {
	header := make([]byte, 100)
	if _, err := file.ReadAt(header, 0); err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	if string(header[:16]) != headerMagic {
		return nil, fmt.Errorf("%w: not an SQLite 3 database", ErrMalformed)
	}
	pageSize := int(binary.BigEndian.Uint16(header[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("%w: page size %d", ErrMalformed, pageSize)
	}
	usable := pageSize - int(header[20])
	if usable < 480 {
		return nil, fmt.Errorf("%w: usable page size %d", ErrMalformed, usable)
	}
	if encoding := binary.BigEndian.Uint32(header[56:60]); encoding != 1 {
		return nil, fmt.Errorf("%w: text encoding %d is not UTF-8", ErrMalformed, encoding)
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	db := &DB{file: file, pageSize: pageSize, usable: usable, pages: uint32(min(info.Size()/int64(pageSize), math.MaxUint32))}
	if err := db.openWAL(path + "-wal"); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() error {
	if db.wal != nil {
		db.wal.Close()
	}
	return db.file.Close()
}

// openWAL indexes the frames of the write-ahead log up to its last valid commit. A frame is valid when its salt
// matches the log header and its cumulative checksum is right: frames left over from before the last checkpoint
// carry an old salt, and a frame being written fails the checksum, so both are ignored as SQLite ignores them.
func (db *DB) openWAL(path string) error {
	wal, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("write-ahead log: %w", err)
	}
	committed, pages := db.readWAL(wal)
	if len(committed) == 0 {
		wal.Close()
		return nil
	}
	db.wal, db.walPages, db.pages = wal, committed, pages
	return nil
}

func (db *DB) readWAL(wal *os.File) (map[uint32]int64, uint32) {
	header := make([]byte, walHeaderSize)
	if _, err := wal.ReadAt(header, 0); err != nil {
		return nil, 0
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(header[0:4]) {
	case walMagicLE:
		order = binary.LittleEndian
	case walMagicBE:
		order = binary.BigEndian
	default:
		return nil, 0
	}
	if binary.BigEndian.Uint32(header[4:8]) != walVersion || int(binary.BigEndian.Uint32(header[8:12])) != db.pageSize {
		return nil, 0
	}
	s0, s1 := walChecksum(order, header[:24], 0, 0)
	if s0 != binary.BigEndian.Uint32(header[24:28]) || s1 != binary.BigEndian.Uint32(header[28:32]) {
		return nil, 0
	}
	salt := header[16:24]

	committed := map[uint32]int64{}
	pending := map[uint32]int64{}
	var pages uint32
	frame := make([]byte, walFrameSize+db.pageSize)
	for offset := int64(walHeaderSize); ; offset += int64(len(frame)) {
		if _, err := wal.ReadAt(frame, offset); err != nil {
			break
		}
		if !bytes.Equal(frame[8:16], salt) {
			break
		}
		s0, s1 = walChecksum(order, frame[:8], s0, s1)
		s0, s1 = walChecksum(order, frame[walFrameSize:], s0, s1)
		if s0 != binary.BigEndian.Uint32(frame[16:20]) || s1 != binary.BigEndian.Uint32(frame[20:24]) {
			break
		}
		page := binary.BigEndian.Uint32(frame[0:4])
		if page == 0 {
			break
		}
		pending[page] = offset + walFrameSize
		if size := binary.BigEndian.Uint32(frame[4:8]); size != 0 {
			for p, at := range pending {
				committed[p] = at
			}
			clear(pending)
			pages = size
		}
	}
	return committed, pages
}

func walChecksum(order binary.ByteOrder, b []byte, s0, s1 uint32) (uint32, uint32) {
	for i := 0; i+8 <= len(b); i += 8 {
		s0 += order.Uint32(b[i:]) + s1
		s1 += order.Uint32(b[i+4:]) + s0
	}
	return s0, s1
}

func (db *DB) page(n uint32) ([]byte, error) {
	if n == 0 || n > db.pages {
		return nil, fmt.Errorf("%w: page %d out of range", ErrMalformed, n)
	}
	buf := make([]byte, db.pageSize)
	var err error
	if at, ok := db.walPages[n]; ok {
		_, err = db.wal.ReadAt(buf, at)
	} else {
		_, err = db.file.ReadAt(buf, int64(n-1)*int64(db.pageSize))
	}
	if err != nil {
		return nil, fmt.Errorf("%w: page %d: %w", ErrMalformed, n, err)
	}
	return buf, nil
}

// Scan calls fn with the values of columns for every row of table, in rowid order. Values are nil, int64,
// float64, string or []byte. A column added by ALTER TABLE after a row was written reads as nil for that row.
func (db *DB) Scan(ctx context.Context, table string, columns []string, fn func(values []any) error) error {
	root, names, rowidAlias, err := db.table(ctx, table)
	if err != nil {
		return err
	}
	indexes := make([]int, len(columns))
	for i, column := range columns {
		indexes[i] = -1
		for j, name := range names {
			if strings.EqualFold(name, column) {
				indexes[i] = j
			}
		}
		if indexes[i] < 0 {
			return fmt.Errorf("%s.%s: no such column", table, column)
		}
	}
	return db.walk(ctx, root, func(rowid int64, payload []byte) error {
		record, err := decodeRecord(payload)
		if err != nil {
			return err
		}
		values := make([]any, len(columns))
		for i, index := range indexes {
			switch {
			case index == rowidAlias:
				values[i] = rowid
			case index < len(record):
				values[i] = record[index]
			}
		}
		return fn(values)
	})
}

// table finds the root page and column names of a table in the schema, which is itself a table rooted at page 1.
func (db *DB) table(ctx context.Context, name string) (uint32, []string, int, error) {
	var root int64
	var sql string
	err := db.walk(ctx, 1, func(_ int64, payload []byte) error {
		record, err := decodeRecord(payload)
		if err != nil {
			return err
		}
		if len(record) < 5 || record[0] != "table" {
			return nil
		}
		if tableName, _ := record[1].(string); strings.EqualFold(tableName, name) {
			root, _ = record[3].(int64)
			sql, _ = record[4].(string)
		}
		return nil
	})
	if err != nil {
		return 0, nil, 0, err
	}
	if root <= 0 || root > math.MaxUint32 {
		return 0, nil, 0, fmt.Errorf("%s: no such table", name)
	}
	columns, rowidAlias, err := parseColumns(sql)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("%s: %w", name, err)
	}
	return uint32(root), columns, rowidAlias, nil
}

// walk visits the cells of a table b-tree in rowid order.
func (db *DB) walk(ctx context.Context, root uint32, fn func(rowid int64, payload []byte) error) error {
	visited := map[uint32]bool{}
	var visit func(n uint32, depth int) error
	visit = func(n uint32, depth int) error {
		if depth > maxTreeDepth || visited[n] {
			return fmt.Errorf("%w: b-tree loop at page %d", ErrMalformed, n)
		}
		visited[n] = true
		if err := ctx.Err(); err != nil {
			return err
		}
		p, err := db.page(n)
		if err != nil {
			return err
		}
		header := 0
		if n == 1 {
			header = 100
		}
		if header+12 > len(p) {
			return fmt.Errorf("%w: page %d header", ErrMalformed, n)
		}
		kind := p[header]
		cells := int(binary.BigEndian.Uint16(p[header+3:]))
		var pointers int
		switch kind {
		case pageLeafTable:
			pointers = header + 8
		case pageInteriorTable:
			pointers = header + 12
		default:
			return fmt.Errorf("%w: page %d is not a table b-tree page", ErrMalformed, n)
		}
		if pointers+2*cells > len(p) {
			return fmt.Errorf("%w: page %d cell count", ErrMalformed, n)
		}
		for i := range cells {
			cell := int(binary.BigEndian.Uint16(p[pointers+2*i:]))
			switch kind {
			case pageLeafTable:
				rowid, payload, err := db.leafCell(p, cell)
				if err != nil {
					return fmt.Errorf("page %d: %w", n, err)
				}
				if err := fn(rowid, payload); err != nil {
					return err
				}
			case pageInteriorTable:
				if cell+4 > len(p) {
					return fmt.Errorf("%w: page %d cell offset", ErrMalformed, n)
				}
				if err := visit(binary.BigEndian.Uint32(p[cell:]), depth+1); err != nil {
					return err
				}
			}
		}
		if kind == pageInteriorTable {
			return visit(binary.BigEndian.Uint32(p[header+8:]), depth+1)
		}
		return nil
	}
	return visit(root, 0)
}

// leafCell returns the rowid and the full payload of a table leaf cell, following its overflow pages.
func (db *DB) leafCell(p []byte, cell int) (int64, []byte, error) {
	if cell >= len(p) {
		return 0, nil, fmt.Errorf("%w: cell offset", ErrMalformed)
	}
	size, n := varint(p[cell:])
	if n == 0 || size < 0 || size > int64(db.pages)*int64(db.usable) {
		return 0, nil, fmt.Errorf("%w: payload size", ErrMalformed)
	}
	cell += n
	rowid, n := varint(p[cell:])
	if n == 0 {
		return 0, nil, fmt.Errorf("%w: rowid", ErrMalformed)
	}
	cell += n

	local := int(size)
	if maxLocal := db.usable - 35; local > maxLocal {
		minLocal := (db.usable-12)*32/255 - 23
		local = minLocal + (int(size)-minLocal)%(db.usable-4)
		if local > maxLocal {
			local = minLocal
		}
	}
	if cell+local > len(p) {
		return 0, nil, fmt.Errorf("%w: payload exceeds page", ErrMalformed)
	}
	payload := make([]byte, 0, size)
	payload = append(payload, p[cell:cell+local]...)
	if local == int(size) {
		return rowid, payload, nil
	}
	if cell+local+4 > len(p) {
		return 0, nil, fmt.Errorf("%w: overflow pointer", ErrMalformed)
	}
	next := binary.BigEndian.Uint32(p[cell+local:])
	for len(payload) < int(size) {
		overflow, err := db.page(next)
		if err != nil {
			return 0, nil, err
		}
		next = binary.BigEndian.Uint32(overflow)
		take := min(db.usable-4, int(size)-len(payload))
		payload = append(payload, overflow[4:4+take]...)
	}
	return rowid, payload, nil
}

func varint(b []byte) (int64, int) {
	var v uint64
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return int64(v<<8 | uint64(b[i])), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i] < 0x80 {
			return int64(v), i + 1
		}
	}
	return 0, 0
}

var intSizes = [...]int{1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8}

func decodeRecord(b []byte) ([]any, error) {
	headerSize, n := varint(b)
	if n == 0 || headerSize < int64(n) || headerSize > int64(len(b)) {
		return nil, fmt.Errorf("%w: record header", ErrMalformed)
	}
	var types []int64
	for at := n; at < int(headerSize); {
		serialType, k := varint(b[at:headerSize])
		if k == 0 {
			return nil, fmt.Errorf("%w: record header", ErrMalformed)
		}
		types = append(types, serialType)
		at += k
	}
	body := b[headerSize:]
	values := make([]any, 0, len(types))
	for _, serialType := range types {
		var size int
		switch {
		case serialType == 0, serialType == 8, serialType == 9:
		case serialType >= 1 && serialType <= 6:
			size = intSizes[serialType]
		case serialType == 7:
			size = 8
		case serialType >= 12:
			size = int((serialType - 12) / 2)
		default:
			return nil, fmt.Errorf("%w: serial type %d", ErrMalformed, serialType)
		}
		if size < 0 || size > len(body) {
			return nil, fmt.Errorf("%w: record body", ErrMalformed)
		}
		field := body[:size]
		body = body[size:]
		switch {
		case serialType == 0:
			values = append(values, nil)
		case serialType == 8, serialType == 9:
			values = append(values, serialType-8)
		case serialType <= 6:
			v := int64(int8(field[0]))
			for _, c := range field[1:] {
				v = v<<8 | int64(c)
			}
			values = append(values, v)
		case serialType == 7:
			values = append(values, math.Float64frombits(binary.BigEndian.Uint64(field)))
		case serialType%2 == 1:
			values = append(values, string(field))
		default:
			values = append(values, bytes.Clone(field))
		}
	}
	return values, nil
}

// parseColumns reads the column names of a CREATE TABLE statement, and the index of the column that aliases the
// rowid (an INTEGER PRIMARY KEY, whose value the record stores as NULL), or -1.
func parseColumns(sql string) ([]string, int, error) {
	sql = stripSQLComments(sql)
	open, end := strings.IndexByte(sql, '('), strings.LastIndexByte(sql, ')')
	if open < 0 || end < open {
		return nil, 0, fmt.Errorf("%w: CREATE TABLE statement", ErrMalformed)
	}
	if strings.Contains(strings.ToUpper(sql[end:]), "WITHOUT") {
		return nil, 0, errors.New("WITHOUT ROWID tables are not supported")
	}
	var columns []string
	rowidAlias := -1
	for _, definition := range splitTopLevel(sql[open+1 : end]) {
		fields := strings.Fields(definition)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN":
			continue
		}
		upper := strings.ToUpper(definition)
		if len(fields) > 1 && strings.ToUpper(fields[1]) == "INTEGER" && strings.Contains(upper, "PRIMARY KEY") && !strings.Contains(upper, "DESC") {
			rowidAlias = len(columns)
		}
		columns = append(columns, strings.Trim(fields[0], "\"`[]"))
	}
	return columns, rowidAlias, nil
}

func stripSQLComments(sql string) string {
	var out strings.Builder
	for i := 0; i < len(sql); i++ {
		switch {
		case strings.HasPrefix(sql[i:], "/*"):
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return out.String()
			}
			i += end + 3
			out.WriteByte(' ')
		case strings.HasPrefix(sql[i:], "--"):
			end := strings.IndexByte(sql[i:], '\n')
			if end < 0 {
				return out.String()
			}
			i += end
			out.WriteByte('\n')
		default:
			out.WriteByte(sql[i])
		}
	}
	return out.String()
}

// splitTopLevel splits column definitions on the commas that are outside parentheses and quotes.
func splitTopLevel(s string) []string {
	var parts []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}
