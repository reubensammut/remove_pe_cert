from cffi import FFI
import ctypes
import argparse
import sys

def strip_file(file_name):
	ffi = FFI()
	ffi.set_unicode(True)

	Kernel32 = ffi.dlopen("kernel32.dll")
	Imagehlp = ffi.dlopen("imagehlp.dll")

	ffi.cdef("""
		typedef struct _SECURITY_ATTRIBUTES {
			DWORD  nLength;
			LPVOID lpSecurityDescriptor;
			BOOL   bInheritHandle;
		} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
		
		HANDLE CreateFileW(
			LPCTSTR               lpFileName,
			DWORD                 dwDesiredAccess,
			DWORD                 dwShareMode,
			LPSECURITY_ATTRIBUTES lpSecurityAttributes,
			DWORD                 dwCreationDisposition,
			DWORD                 dwFlagsAndAttributes,
			HANDLE                hTemplateFile
		);
		
		BOOL ImageEnumerateCertificates(
			HANDLE FileHandle,
			WORD   TypeFilter,
			PDWORD CertificateCount,
			PDWORD Indices,
			DWORD  IndexCount
		);
		
		BOOL ImageRemoveCertificate(
			HANDLE FileHandle,
			DWORD  Index
		);
		
		BOOL WINAPI CloseHandle(
			HANDLE hObject
		);
	""")

	GENERIC_READ = 0x80000000
	GENERIC_WRITE = 0x40000000
	FILE_SHARE_READ = 1
	FILE_SHARE_DELETE = 4
	OPEN_EXISTING = 3
	CERT_SECTION_TYPE_ANY = 255
	INVALID_HANDLE_VALUE = ffi.cast("HANDLE", -1)

	desired_access = GENERIC_READ | GENERIC_WRITE
	share_mode = FILE_SHARE_READ | FILE_SHARE_DELETE

	print("[+] Opening file [{}]".format(file_name))
	handle = Kernel32.CreateFileW( file_name, desired_access, share_mode, ffi.NULL, OPEN_EXISTING, 0, ffi.NULL )
	if( handle == INVALID_HANDLE_VALUE ):
		print("[-] File not found")
		sys.exit(1)
		
	count = ffi.new("PDWORD")
	print("[+] Enumerating certificates")
	if(Imagehlp.ImageEnumerateCertificates(handle, CERT_SECTION_TYPE_ANY, count, ffi.NULL, 0)):
		print("[-] Found {} certificate(s)".format(count[0]))
		
		for x in range(count[0]):
			print("[+] Removing certificate [{}]".format(x + 1))
			if(Imagehlp.ImageRemoveCertificate( handle, x )):
				print("[-] Removed Certificate!")
	else:
		print("[-] Image is not a PE")

	Kernel32.CloseHandle( handle )

	
def main():
	parser = argparse.ArgumentParser(description="This script removes certificates from a PE file")
	parser.add_argument("filename", help="PE File you want to remove certificates from")
	args = parser.parse_args()
	
	file_name = args.filename
	
	strip_file(file_name)

if __name__ == "__main__":
	main()
