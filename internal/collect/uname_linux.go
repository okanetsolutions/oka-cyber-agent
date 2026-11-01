package collect

import "syscall"

func systemUname() (Uname, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return Uname{}, err
	}
	return Uname{
		Nodename: utsString(u.Nodename[:]),
		Release:  utsString(u.Release[:]),
		Machine:  utsString(u.Machine[:]),
	}, nil
}

func utsString[T int8 | uint8](field []T) string {
	b := make([]byte, 0, len(field))
	for _, c := range field {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
