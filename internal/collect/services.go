package collect

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const tcpListen = "0A"

type ServicesCollector struct {
	Root string
}

func (ServicesCollector) Name() string { return "services" }

// Collect lists listening TCP sockets. Process names are only known for sockets whose owning process the agent
// may inspect; the rest are reported without one.
func (c ServicesCollector) Collect(ctx context.Context, inv *Inventory) error {
	var sockets []listeningSocket
	for _, protocol := range []string{"tcp", "tcp6"} {
		found, err := c.readTable(protocol)
		if err != nil {
			return err
		}
		sockets = append(sockets, found...)
	}
	owners := c.socketOwners(ctx)
	for _, s := range sockets {
		service := Service{Protocol: s.protocol, Address: s.address.String(), Port: s.port}
		if owner, ok := owners[s.inode]; ok {
			service.PID = owner.pid
			service.Process = owner.process
		}
		inv.Services = append(inv.Services, service)
	}
	return nil
}

type listeningSocket struct {
	protocol string
	address  netip.Addr
	port     int
	inode    string
}

func (c ServicesCollector) readTable(protocol string) ([]listeningSocket, error) {
	f, err := os.Open(filepath.Join(c.Root, "proc/net", protocol))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("/proc/net/%s: %w", protocol, err)
	}
	defer f.Close()
	sockets, err := parseProcNetTCP(f, protocol)
	if err != nil {
		return nil, fmt.Errorf("/proc/net/%s: %w", protocol, err)
	}
	return sockets, nil
}

func parseProcNetTCP(r io.Reader, protocol string) ([]listeningSocket, error) {
	var sockets []listeningSocket
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != tcpListen {
			continue
		}
		hexAddress, hexPort, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		address, ok := parseProcNetAddress(hexAddress)
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil || port == 0 {
			continue
		}
		sockets = append(sockets, listeningSocket{protocol: protocol, address: address, port: int(port), inode: fields[9]})
	}
	return sockets, scanner.Err()
}

// parseProcNetAddress decodes the kernel's hex address: 32 bit words in host (little endian) byte order.
func parseProcNetAddress(s string) (netip.Addr, bool) {
	raw, err := hex.DecodeString(s)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, false
	}
	decoded := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(decoded[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	address, ok := netip.AddrFromSlice(decoded)
	return address, ok
}

type socketOwner struct {
	pid     int
	process string
}

// socketOwners maps socket inodes to the lowest PID holding them. Processes the agent may not inspect are
// skipped silently: without root it only sees its own.
func (c ServicesCollector) socketOwners(ctx context.Context) map[string]socketOwner {
	owners := map[string]socketOwner{}
	procDir := filepath.Join(c.Root, "proc")
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return owners
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return owners
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(procDir, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var process string
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := strings.CutPrefix(target, "socket:[")
			if !ok {
				continue
			}
			inode = strings.TrimSuffix(inode, "]")
			if existing, ok := owners[inode]; ok && existing.pid < pid {
				continue
			}
			if process == "" {
				process = readComm(filepath.Join(procDir, entry.Name(), "comm"))
			}
			owners[inode] = socketOwner{pid: pid, process: process}
		}
	}
	return owners
}

func readComm(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
