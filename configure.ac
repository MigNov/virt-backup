AC_INIT([virt-backup], [0.0.3], [mignov@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AM_PROG_CC_C_O
AC_CHECK_LIB([virt], [virConnectOpen], [], AC_MSG_ERROR([You need libvirt to compile this utility]))
AC_CHECK_LIB([xml2], [xmlParseFile], [], AC_MSG_ERROR([You need libxml to compile this utility]))
AC_CHECK_LIB([blkid], [blkid_get_dev], [], AC_MSG_ERROR([You need libblkid to compile this utility]))
AC_CHECK_LIB([lzma], [lzma_stream_decoder], [])
AC_CHECK_LIB([pci], [pci_scan_bus], [])
AC_CHECK_HEADERS([libxml/parser.h])
if test "$HAVE_LIBXML_PARSER_H" = ""; then
  AC_CHECK_PROGS([PKGCONFIG], [pkg-config], [:])
  if test "$PKGCONFIG" = :; then
    AC_MSG_ERROR("Cannot find libxml2.0 headers on path and pkg-config is not found")
  fi
  AM_CONDITIONAL([USE_PKGCONFIG], [true])
fi

# Enable sensors
AC_ARG_ENABLE([sensors],
    AS_HELP_STRING([--enable-sensors], [Enable sensors feature from sysfs]))

AS_IF([test "x$enable_sensors" = "xyes"], [
  AC_DEFINE([HAVE_SENSORS],[1],[Add sensors support])
])

# Compression level
AC_ARG_ENABLE([buffer-size],
    AS_HELP_STRING([--enable-buffer-size=SIZE], [Enables copy/compress with buffer size specified in bytes]))

AS_IF([test "x$enable_buffer_size" != "x"], [
  AC_DEFINE_UNQUOTED([BUFFER_SIZE],[$enable_buffer_size],[Buffer size for copy/compress operations])
])

# Compression level
  AC_ARG_ENABLE([compression-level],
      AS_HELP_STRING([--enable-compression-level=LEVEL], [Enables compression with compression level specified. Can have values from 1 to 9. Default value is 5]))
  AS_IF([test "x$enable_compression_level" != "x"], [
    AC_DEFINE_UNQUOTED([COMPRESSION_LEVEL],[$enable_compression_level],[Set the compression level])
  ])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
