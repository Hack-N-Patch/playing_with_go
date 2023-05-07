package macOsTriage

import (
	// "debug/macho"
	"github.com/blacktop/go-macho"
	"github.com/stretchr/testify/assert"
	"macOsTriage/internal"
	"os"
	"testing"
)

func TestGetAsciiStrings(t *testing.T) {
	assert.Equal(
		t,
		[]string{"__mod_init_func"},
		internal.GetAsciiStrings([]byte("\u0000\u01200\u0000\u0037\u0000\u0000\u4300\u0000\u0000\u0000__mod_init_func\u0000")),
	)
}

func TestCheckVirusTotal(t *testing.T) {
	positives, total := internal.CheckVirusTotal("553d3aab148c4d11d76b4f96b5664b42cfc38c236dacbaf9e42d6a6bcf0115eb")

	assert.Equal(
		t,
		0,
		positives,
	)

	assert.Equal(
		t,
		62,
		total,
	)
}

func TestDetermineFileType(t *testing.T) {
	fileContents, err := os.ReadFile("/bin/ls")
	if err != nil {
		panic(err)
	}
	assert.Equal(
		t,
		"application/x-mach-binary",
		internal.DetermineFileType(fileContents),
	)
}

func TestGetSectionNames(t *testing.T) {
	fileContents, err := macho.OpenFat("/bin/ls")
	if err != nil {
		panic(err)
	}
	defer fileContents.Close()
	assert.Equal(t,
		[]string{
			"__text",
			"__stubs",
			"__stub_helper",
			"__const",
			"__cstring",
			"__unwind_info",
			"__nl_symbol_ptr",
			"__got",
			"__la_symbol_ptr",
			"__const",
			"__data",
			"__common",
			"__bss",
		},
		internal.GetSectionNames(fileContents.Arches[0]))
}

func TestGetMachOImportedSymbols(t *testing.T) {
	fileContents, err := macho.OpenFat("/bin/ls")
	if err != nil {
		panic(err)
	}
	defer fileContents.Close()

	assert.Equal(t,
		[]string{
			"__DefaultRuneLocale",
			"___assert_rtn",
			"___bzero",
			"___error",
			"___maskrune",
			"___stack_chk_fail",
			"___stack_chk_guard",
			"___stderrp",
			"___stdoutp",
			"___tolower",
			"_abort",
			"_acl_free",
			"_acl_get_entry",
			"_acl_get_flag_np",
			"_acl_get_flagset_np",
			"_acl_get_link_np",
			"_acl_get_perm_np",
			"_acl_get_permset",
			"_acl_get_qualifier",
			"_acl_get_tag_type",
			"_calloc",
			"_compat_mode",
			"_err",
			"_errx",
			"_exit",
			"_ferror",
			"_fflagstostr",
			"_fflush",
			"_fprintf",
			"_fputc",
			"_fputs",
			"_free",
			"_fts_children$INODE64",
			"_fts_close$INODE64",
			"_fts_open$INODE64",
			"_fts_read$INODE64",
			"_fts_set$INODE64",
			"_getbsize",
			"_getenv",
			"_getopt_long",
			"_getpid",
			"_getuid",
			"_getxattr",
			"_group_from_gid",
			"_humanize_number",
			"_ioctl",
			"_isatty",
			"_kill",
			"_listxattr",
			"_localtime",
			"_malloc",
			"_mbr_identifier_translate",
			"_mbrtowc",
			"_memchr",
			"_nl_langinfo",
			"_optarg",
			"_optind",
			"_printf",
			"_putchar",
			"_puts",
			"_readlink",
			"_realloc",
			"_reallocf",
			"_setenv",
			"_setlocale",
			"_signal",
			"_snprintf",
			"_strcmp",
			"_strcoll",
			"_strcpy",
			"_strdup",
			"_strerror",
			"_strftime",
			"_strlen",
			"_strmode",
			"_strstr",
			"_strtonum",
			"_strtoul",
			"_sysctlbyname",
			"_tgetent",
			"_tgetstr",
			"_tgoto",
			"_time",
			"_tputs",
			"_user_from_uid",
			"_uuid_unparse_upper",
			"_warn",
			"_warnx",
			"_wcwidth",
			"_write",
			"dyld_stub_binder",
		},
		internal.GetMachOImportedSymbols(fileContents.Arches[0]))
}

func TestGetMachOLibraries(t *testing.T) {
	fileContents, err := macho.OpenFat("/bin/ls")
	if err != nil {
		panic(err)
	}
	defer fileContents.Close()
	assert.Equal(t, []string{
		"/usr/lib/libutil.dylib",
		"/usr/lib/libncurses.5.4.dylib",
		"/usr/lib/libSystem.B.dylib",
	},
		internal.GetMachOLibraries(fileContents.Arches[0]))
}
