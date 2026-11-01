package sqlite

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The fixtures were written by SQLite 3.46 through Python's sqlite3 module. wal.sqlite-wal holds two transactions
// that were committed but not checkpointed: one inserts row 2, the next changes row 1 and inserts row 3.
// restarted.sqlite is wal.sqlite after a checkpoint of that log, and restarted.sqlite-wal the restarted log (new
// salts) of the next transaction, which inserts row 4. uncheckpointed.sqlite was switched to WAL mode before its
// first table was created, so only its log holds the schema and the text encoding.

func openFixture(t *testing.T, path string) *DB {
	t.Helper()
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func scanAll(t *testing.T, db *DB, table string, columns ...string) [][]any {
	t.Helper()
	var rows [][]any
	if err := db.Scan(context.Background(), table, columns, func(values []any) error {
		rows = append(rows, values)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestScanDecodesEveryStorageClass(t *testing.T) {
	db := openFixture(t, filepath.Join("testdata", "types.sqlite"))
	rows := scanAll(t, db, "item", "id", "name", "value", "added")
	want := [][]any{
		{int64(1), "null", nil, nil},
		{int64(2), "zero", int64(0), nil},
		{int64(3), "one", int64(1), nil},
		{int64(4), "int8", int64(-100), nil},
		{int64(5), "int16", int64(1000), nil},
		{int64(6), "int24", int64(-100000), nil},
		{int64(7), "int32", int64(100000000), nil},
		{int64(8), "int48", int64(-100000000000), nil},
		{int64(9), "int64", int64(9223372036854775807), nil},
		{int64(10), "float", 1.5, nil},
		{int64(11), "text", "héllo", nil},
		{int64(12), "blob", []byte{0x00, 0xff}, nil},
		{int64(13), "long", strings.Repeat("x", 10000), nil},
		{int64(14), "after", "v", "set"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %v\nwant %v", rows, want)
	}
}

func TestScanWalksMultiLevelTreesInRowidOrder(t *testing.T) {
	db := openFixture(t, filepath.Join("testdata", "types.sqlite"))
	rows := scanAll(t, db, "many", "n", "id")
	if len(rows) != 5000 {
		t.Fatalf("rows = %d, want 5000", len(rows))
	}
	for i, row := range rows {
		if row[0] != int64(i*7) || row[1] != int64(i+1) {
			t.Fatalf("row %d = %v", i, row)
		}
	}
}

func TestScanRejectsUnknownTablesAndColumns(t *testing.T) {
	db := openFixture(t, filepath.Join("testdata", "types.sqlite"))
	ignore := func([]any) error { return nil }
	for _, tt := range []struct{ table, column string }{{"missing", "id"}, {"item", "missing"}, {"pairs", "a"}, {"many_n", "n"}} {
		if err := db.Scan(context.Background(), tt.table, []string{tt.column}, ignore); err == nil {
			t.Errorf("Scan(%s.%s) succeeded, want an error", tt.table, tt.column)
		}
	}
}

func TestScanStopsOnCallbackErrorAndCancellation(t *testing.T) {
	db := openFixture(t, filepath.Join("testdata", "types.sqlite"))
	stop := errors.New("stop")
	calls := 0
	err := db.Scan(context.Background(), "many", []string{"n"}, func([]any) error {
		calls++
		return stop
	})
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("err = %v after %d calls, want stop after 1", err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := db.Scan(ctx, "many", []string{"n"}, func([]any) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func copyFixture(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, names[0])
}

func repoRows(t *testing.T, path string) [][]any {
	t.Helper()
	return scanAll(t, openFixture(t, path), "repo", "id", "repoid")
}

func TestScanAppliesCommittedWriteAheadLogFrames(t *testing.T) {
	path := copyFixture(t, "wal.sqlite", "wal.sqlite-wal")
	want := [][]any{{int64(1), "crb"}, {int64(2), "appstream"}, {int64(3), "epel"}}
	if rows := repoRows(t, path); !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %v, want %v", rows, want)
	}
	if _, err := os.Stat(path + "-shm"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("reading created %s-shm (err %v); the reader must not write", path, err)
	}
}

func TestScanIgnoresTornAndStaleWriteAheadLogFrames(t *testing.T) {
	corrupt := func(t *testing.T, offset func(size int) int) string {
		path := copyFixture(t, "wal.sqlite", "wal.sqlite-wal")
		b, err := os.ReadFile(path + "-wal")
		if err != nil {
			t.Fatal(err)
		}
		b[offset(len(b))] ^= 0xff
		if err := os.WriteFile(path+"-wal", b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Run("last frame fails its checksum", func(t *testing.T) {
		path := corrupt(t, func(size int) int { return size - 1 })
		want := [][]any{{int64(1), "baseos"}, {int64(2), "appstream"}}
		if rows := repoRows(t, path); !reflect.DeepEqual(rows, want) {
			t.Fatalf("rows = %v, want the first transaction only %v", rows, want)
		}
	})
	t.Run("log header does not match", func(t *testing.T) {
		path := corrupt(t, func(int) int { return 16 })
		want := [][]any{{int64(1), "baseos"}}
		if rows := repoRows(t, path); !reflect.DeepEqual(rows, want) {
			t.Fatalf("rows = %v, want the checkpointed rows only %v", rows, want)
		}
	})
	t.Run("no log", func(t *testing.T) {
		want := [][]any{{int64(1), "baseos"}}
		if rows := repoRows(t, copyFixture(t, "wal.sqlite")); !reflect.DeepEqual(rows, want) {
			t.Fatalf("rows = %v, want %v", rows, want)
		}
	})
}

// overwrite replaces the content of the file at path in place, as a writer does, with the fixture name, or
// removes the file when name is "".
func overwrite(t *testing.T, path, name string) {
	t.Helper()
	if name == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// betweenReads runs change after Open read the main file and before it reads the write-ahead log, and returns a
// pointer to the number of reads of the main file.
func betweenReads(t *testing.T, change func(read int)) *int {
	t.Helper()
	hook, delay := afterMainRead, retryDelay
	t.Cleanup(func() { afterMainRead, retryDelay = hook, delay })
	reads := 0
	afterMainRead = func() {
		reads++
		change(reads)
	}
	retryDelay = time.Millisecond
	return &reads
}

func TestOpenReadsAgainWhenTheLogIsRestartedDuringTheRead(t *testing.T) {
	path := copyFixture(t, "wal.sqlite", "wal.sqlite-wal")
	reads := betweenReads(t, func(read int) {
		if read == 1 {
			overwrite(t, path, "restarted.sqlite")
			overwrite(t, path+"-wal", "restarted.sqlite-wal")
		}
	})
	want := [][]any{{int64(1), "crb"}, {int64(2), "appstream"}, {int64(3), "epel"}, {int64(4), "highavailability"}}
	if rows := repoRows(t, path); !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %v, want the database after the restart %v", rows, want)
	}
	if *reads != 2 {
		t.Fatalf("main file read %d times, want 2: the restart must be detected", *reads)
	}
}

func TestOpenTakesCheckpointedPagesFromTheLog(t *testing.T) {
	path := copyFixture(t, "wal.sqlite", "wal.sqlite-wal")
	betweenReads(t, func(read int) {
		if read == 1 {
			overwrite(t, path, "restarted.sqlite")
		}
	})
	want := [][]any{{int64(1), "crb"}, {int64(2), "appstream"}, {int64(3), "epel"}}
	if rows := repoRows(t, path); !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %v, want %v", rows, want)
	}
}

func TestOpenReturnsErrBusyWhileTheDatabaseKeepsChanging(t *testing.T) {
	path := copyFixture(t, "wal.sqlite", "wal.sqlite-wal")
	reads := betweenReads(t, func(read int) {
		prefix := "restarted"
		if read%2 == 0 {
			prefix = "wal"
		}
		overwrite(t, path, prefix+".sqlite")
		overwrite(t, path+"-wal", prefix+".sqlite-wal")
	})
	if _, err := Open(context.Background(), path); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	if *reads != readAttempts {
		t.Fatalf("main file read %d times, want %d", *reads, readAttempts)
	}
}

func TestOpenWaitsForAHotRollbackJournal(t *testing.T) {
	hot := append([]byte(journalMagic), make([]byte, 504)...)
	t.Run("stays hot", func(t *testing.T) {
		path := copyFixture(t, "types.sqlite")
		if err := os.WriteFile(path+"-journal", hot, 0o600); err != nil {
			t.Fatal(err)
		}
		betweenReads(t, func(int) {})
		if _, err := Open(context.Background(), path); !errors.Is(err, ErrBusy) {
			t.Fatalf("err = %v, want ErrBusy", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := Open(ctx, path); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
	t.Run("transaction ends", func(t *testing.T) {
		path := copyFixture(t, "types.sqlite")
		if err := os.WriteFile(path+"-journal", hot, 0o600); err != nil {
			t.Fatal(err)
		}
		reads := betweenReads(t, func(read int) {
			if read == 1 {
				overwrite(t, path+"-journal", "")
			}
		})
		if rows := scanAll(t, openFixture(t, path), "item", "id"); len(rows) != 14 || *reads != 2 {
			t.Fatalf("rows = %d after %d reads, want 14 after 2", len(rows), *reads)
		}
	})
	t.Run("persisted with a zeroed header", func(t *testing.T) {
		path := copyFixture(t, "types.sqlite")
		if err := os.WriteFile(path+"-journal", make([]byte, 512), 0o600); err != nil {
			t.Fatal(err)
		}
		if rows := scanAll(t, openFixture(t, path), "item", "id"); len(rows) != 14 {
			t.Fatalf("rows = %d, want 14", len(rows))
		}
	})
}

func TestScanReadsTheCopyTakenByOpen(t *testing.T) {
	path := copyFixture(t, "wal.sqlite", "wal.sqlite-wal")
	db := openFixture(t, path)
	overwrite(t, path, "restarted.sqlite")
	overwrite(t, path+"-wal", "restarted.sqlite-wal")
	want := [][]any{{int64(1), "crb"}, {int64(2), "appstream"}, {int64(3), "epel"}}
	if rows := scanAll(t, db, "repo", "id", "repoid"); !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %v, want the database as Open read it %v", rows, want)
	}
}

func TestOpenReadsTheTextEncodingFromTheLog(t *testing.T) {
	path := copyFixture(t, "uncheckpointed.sqlite", "uncheckpointed.sqlite-wal")
	want := [][]any{{int64(1), "baseos"}}
	if rows := repoRows(t, path); !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %v, want %v", rows, want)
	}
}

func TestOpenRejectsFilesThatAreNotDatabases(t *testing.T) {
	dir := t.TempDir()
	types, err := os.ReadFile(filepath.Join("testdata", "types.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"empty":     nil,
		"text":      []byte(strings.Repeat("not a database\n", 20)),
		"truncated": types[:60],
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(context.Background(), path); !errors.Is(err, ErrMalformed) {
			t.Errorf("Open(%s) err = %v, want ErrMalformed", name, err)
		}
	}
	if _, err := Open(context.Background(), filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open(missing) err = %v, want fs.ErrNotExist", err)
	}
}

func TestScanReportsTruncatedDatabasesAsMalformed(t *testing.T) {
	types, err := os.ReadFile(filepath.Join("testdata", "types.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "truncated.sqlite")
	if err := os.WriteFile(path, types[:8*4096], 0o600); err != nil {
		t.Fatal(err)
	}
	db := openFixture(t, path)
	if err := db.Scan(context.Background(), "many", []string{"n"}, func([]any) error { return nil }); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestParseColumns(t *testing.T) {
	columns, rowidAlias, err := parseColumns("CREATE TABLE t (\n  id INTEGER PRIMARY KEY, /* a, b */\n  \"name\" TEXT DEFAULT 'x,y', -- c, d\n  n DECIMAL(10, 2),\n  CONSTRAINT u UNIQUE (name, n)\n, added TEXT)")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(columns, []string{"id", "name", "n", "added"}) || rowidAlias != 0 {
		t.Fatalf("columns = %q, rowid alias %d", columns, rowidAlias)
	}
	if _, rowidAlias, _ := parseColumns("CREATE TABLE t (id INT PRIMARY KEY, v)"); rowidAlias != -1 {
		t.Fatalf("INT PRIMARY KEY is not a rowid alias, got %d", rowidAlias)
	}
}

func FuzzScan(f *testing.F) {
	for _, name := range []string{"types.sqlite", "wal.sqlite"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b[:min(len(b), 16384)])
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		path := filepath.Join(t.TempDir(), "fuzz.sqlite")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := Open(context.Background(), path)
		if err != nil {
			return
		}
		for _, table := range []string{"item", "many", "repo"} {
			_ = db.Scan(context.Background(), table, []string{"id"}, func([]any) error { return nil })
		}
	})
}
