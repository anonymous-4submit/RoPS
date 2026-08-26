#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Callable-name canonicalization for Stage 3.

``canon()`` maps a (module, name) reference to its canonical form in two steps:

1. protocol-conditional compatibility remapping (CPython ``_compat_pickle``,
   applied only when ``protocol < 3`` -- the same order ``Unpickler.find_class``
   uses), and
2. alias folding for C-accelerator / platform modules (``_io`` -> ``io``,
   ``posix`` -> ``os``, ...) using the machine-derived tables below.

The alias tables were generated offline by checking object identity
(``getattr(A, n) is getattr(B, n)``) on Python 3.11 / Linux; they are pure data.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

try:
    from pickle import _compat_pickle as _cp
    IMPORT_MAPPING: Dict[str, str] = dict(_cp.IMPORT_MAPPING)
    NAME_MAPPING: Dict[Tuple[str, str], Tuple[str, str]] = dict(_cp.NAME_MAPPING)
except Exception:                                        # pragma: no cover
    IMPORT_MAPPING, NAME_MAPPING = {}, {}

__all__ = ["canon", "CanonResult", "split_qualname",
           "IMPORT_MAPPING", "NAME_MAPPING", "MODULE_ALIAS", "NAME_ALIAS"]


# ──────────────────────────────────────────────────────────────────────────
# Alias tables (generated data)
# ──────────────────────────────────────────────────────────────────────────
MODULE_ALIAS = {
    '_abc': 'abc',
    '_ast': 'ast',
    '_bisect': 'bisect',
    '_codecs': 'codecs',
    '_collections': 'collections',
    '_csv': 'csv',
    '_datetime': 'datetime',
    '_decimal': 'decimal',
    '_functools': 'functools',
    '_hashlib': 'hashlib',
    '_heapq': 'heapq',
    '_io': 'io',
    '_operator': 'operator',
    '_pickle': 'pickle',
    '_queue': 'queue',
    '_socket': 'socket',
    '_ssl': 'ssl',
    '_statistics': 'statistics',
    '_struct': 'struct',
    '_warnings': 'warnings',
    '_weakref': 'weakref',
    'posix': 'os',
}

NAME_ALIAS = {
    '_abc': frozenset({
        '_abc_init', '_abc_instancecheck', '_abc_register', '_abc_subclasscheck', '_get_dump', '_reset_caches',
        '_reset_registry', 'get_cache_token',
    }),
    '_ast': frozenset({
        'AST', 'Add', 'And', 'AnnAssign', 'Assert', 'Assign',
        'AsyncFor', 'AsyncFunctionDef', 'AsyncWith', 'Attribute', 'AugAssign', 'Await',
        'BinOp', 'BitAnd', 'BitOr', 'BitXor', 'BoolOp', 'Break',
        'Call', 'ClassDef', 'Compare', 'Constant', 'Continue', 'Del',
        'Delete', 'Dict', 'DictComp', 'Div', 'Eq', 'ExceptHandler',
        'Expr', 'Expression', 'FloorDiv', 'For', 'FormattedValue', 'FunctionDef',
        'FunctionType', 'GeneratorExp', 'Global', 'Gt', 'GtE', 'If',
        'IfExp', 'Import', 'ImportFrom', 'In', 'Interactive', 'Invert',
        'Is', 'IsNot', 'JoinedStr', 'LShift', 'Lambda', 'List',
        'ListComp', 'Load', 'Lt', 'LtE', 'MatMult', 'Match',
        'MatchAs', 'MatchClass', 'MatchMapping', 'MatchOr', 'MatchSequence', 'MatchSingleton',
        'MatchStar', 'MatchValue', 'Mod', 'Module', 'Mult', 'Name',
        'NamedExpr', 'Nonlocal', 'Not', 'NotEq', 'NotIn', 'Or',
        'Pass', 'Pow', 'PyCF_ALLOW_TOP_LEVEL_AWAIT', 'PyCF_ONLY_AST', 'PyCF_TYPE_COMMENTS', 'RShift',
        'Raise', 'Return', 'Set', 'SetComp', 'Slice', 'Starred',
        'Store', 'Sub', 'Subscript', 'Try', 'TryStar', 'Tuple',
        'TypeIgnore', 'UAdd', 'USub', 'UnaryOp', 'While', 'With',
        'Yield', 'YieldFrom', 'alias', 'arg', 'arguments', 'boolop',
        'cmpop', 'comprehension', 'excepthandler', 'expr', 'expr_context', 'keyword',
        'match_case', 'mod', 'operator', 'pattern', 'stmt', 'type_ignore',
        'unaryop', 'withitem',
    }),
    '_bisect': frozenset({
        'bisect_left', 'bisect_right', 'insort_left', 'insort_right',
    }),
    '_codecs': frozenset({
        'ascii_decode', 'ascii_encode', 'charmap_build', 'charmap_decode', 'charmap_encode', 'decode',
        'encode', 'escape_decode', 'escape_encode', 'latin_1_decode', 'latin_1_encode', 'lookup',
        'lookup_error', 'raw_unicode_escape_decode', 'raw_unicode_escape_encode', 'readbuffer_encode', 'register', 'register_error',
        'unicode_escape_decode', 'unicode_escape_encode', 'unregister', 'utf_16_be_decode', 'utf_16_be_encode', 'utf_16_decode',
        'utf_16_encode', 'utf_16_ex_decode', 'utf_16_le_decode', 'utf_16_le_encode', 'utf_32_be_decode', 'utf_32_be_encode',
        'utf_32_decode', 'utf_32_encode', 'utf_32_ex_decode', 'utf_32_le_decode', 'utf_32_le_encode', 'utf_7_decode',
        'utf_7_encode', 'utf_8_decode', 'utf_8_encode',
    }),
    '_collections': frozenset({
        'OrderedDict', '_count_elements', '_tuplegetter', 'defaultdict', 'deque',
    }),
    '_csv': frozenset({
        'Error', 'QUOTE_ALL', 'QUOTE_MINIMAL', 'QUOTE_NONE', 'QUOTE_NONNUMERIC', 'field_size_limit',
        'get_dialect', 'list_dialects', 'reader', 'register_dialect', 'unregister_dialect', 'writer',
    }),
    '_datetime': frozenset({
        'MAXYEAR', 'MINYEAR', 'UTC', 'date', 'datetime', 'datetime_CAPI',
        'time', 'timedelta', 'timezone', 'tzinfo',
    }),
    '_decimal': frozenset({
        'BasicContext', 'Clamped', 'Context', 'ConversionSyntax', 'Decimal', 'DecimalException',
        'DecimalTuple', 'DefaultContext', 'DivisionByZero', 'DivisionImpossible', 'DivisionUndefined', 'ExtendedContext',
        'FloatOperation', 'HAVE_CONTEXTVAR', 'HAVE_THREADS', 'Inexact', 'InvalidContext', 'InvalidOperation',
        'MAX_EMAX', 'MAX_PREC', 'MIN_EMIN', 'MIN_ETINY', 'Overflow', 'ROUND_05UP',
        'ROUND_CEILING', 'ROUND_DOWN', 'ROUND_FLOOR', 'ROUND_HALF_DOWN', 'ROUND_HALF_EVEN', 'ROUND_HALF_UP',
        'ROUND_UP', 'Rounded', 'Subnormal', 'Underflow', 'getcontext', 'localcontext',
        'setcontext',
    }),
    '_functools': frozenset({
        '_lru_cache_wrapper', 'cmp_to_key', 'partial', 'reduce',
    }),
    '_hashlib': frozenset({
        'pbkdf2_hmac', 'scrypt',
    }),
    '_heapq': frozenset({
        '_heapify_max', '_heappop_max', '_heapreplace_max', 'heapify', 'heappop', 'heappush',
        'heappushpop', 'heapreplace',
    }),
    '_io': frozenset({
        'BlockingIOError', 'BufferedRWPair', 'BufferedRandom', 'BufferedReader', 'BufferedWriter', 'BytesIO',
        'DEFAULT_BUFFER_SIZE', 'FileIO', 'IncrementalNewlineDecoder', 'StringIO', 'TextIOWrapper', 'UnsupportedOperation',
        'open', 'open_code', 'text_encoding',
    }),
    '_operator': frozenset({
        'abs', 'add', 'and_', 'attrgetter', 'call', 'concat',
        'contains', 'countOf', 'delitem', 'eq', 'floordiv', 'ge',
        'getitem', 'gt', 'iadd', 'iand', 'iconcat', 'ifloordiv',
        'ilshift', 'imatmul', 'imod', 'imul', 'index', 'indexOf',
        'inv', 'invert', 'ior', 'ipow', 'irshift', 'is_',
        'is_not', 'isub', 'itemgetter', 'itruediv', 'ixor', 'le',
        'length_hint', 'lshift', 'lt', 'matmul', 'methodcaller', 'mod',
        'mul', 'ne', 'neg', 'not_', 'or_', 'pos',
        'pow', 'rshift', 'setitem', 'sub', 'truediv', 'truth',
        'xor',
    }),
    '_pickle': frozenset({
        'PickleBuffer', 'PickleError', 'Pickler', 'PicklingError', 'Unpickler', 'UnpicklingError',
        'dump', 'dumps', 'load', 'loads',
    }),
    '_queue': frozenset({
        'Empty', 'SimpleQueue',
    }),
    '_socket': frozenset({
        'AF_DECnet', 'ALG_OP_DECRYPT', 'ALG_OP_ENCRYPT', 'ALG_OP_SIGN', 'ALG_OP_VERIFY', 'ALG_SET_AEAD_ASSOCLEN',
        'ALG_SET_AEAD_AUTHSIZE', 'ALG_SET_IV', 'ALG_SET_KEY', 'ALG_SET_OP', 'ALG_SET_PUBKEY', 'BDADDR_ANY',
        'BDADDR_LOCAL', 'BTPROTO_HCI', 'BTPROTO_L2CAP', 'BTPROTO_RFCOMM', 'BTPROTO_SCO', 'CAN_BCM',
        'CAN_BCM_CAN_FD_FRAME', 'CAN_BCM_RX_ANNOUNCE_RESUME', 'CAN_BCM_RX_CHANGED', 'CAN_BCM_RX_CHECK_DLC', 'CAN_BCM_RX_DELETE', 'CAN_BCM_RX_FILTER_ID',
        'CAN_BCM_RX_NO_AUTOTIMER', 'CAN_BCM_RX_READ', 'CAN_BCM_RX_RTR_FRAME', 'CAN_BCM_RX_SETUP', 'CAN_BCM_RX_STATUS', 'CAN_BCM_RX_TIMEOUT',
        'CAN_BCM_SETTIMER', 'CAN_BCM_STARTTIMER', 'CAN_BCM_TX_ANNOUNCE', 'CAN_BCM_TX_COUNTEVT', 'CAN_BCM_TX_CP_CAN_ID', 'CAN_BCM_TX_DELETE',
        'CAN_BCM_TX_EXPIRED', 'CAN_BCM_TX_READ', 'CAN_BCM_TX_RESET_MULTI_IDX', 'CAN_BCM_TX_SEND', 'CAN_BCM_TX_SETUP', 'CAN_BCM_TX_STATUS',
        'CAN_EFF_FLAG', 'CAN_EFF_MASK', 'CAN_ERR_FLAG', 'CAN_ERR_MASK', 'CAN_ISOTP', 'CAN_J1939',
        'CAN_RAW', 'CAN_RAW_FD_FRAMES', 'CAN_RAW_FILTER', 'CAN_RAW_JOIN_FILTERS', 'CAN_RAW_LOOPBACK', 'CAN_RAW_RECV_OWN_MSGS',
        'CAN_RTR_FLAG', 'CAN_SFF_MASK', 'CAPI', 'CMSG_LEN', 'CMSG_SPACE', 'EAI_ADDRFAMILY',
        'EAI_AGAIN', 'EAI_BADFLAGS', 'EAI_FAIL', 'EAI_FAMILY', 'EAI_MEMORY', 'EAI_NODATA',
        'EAI_NONAME', 'EAI_OVERFLOW', 'EAI_SERVICE', 'EAI_SOCKTYPE', 'EAI_SYSTEM', 'HCI_DATA_DIR',
        'HCI_FILTER', 'HCI_TIME_STAMP', 'INADDR_ALLHOSTS_GROUP', 'INADDR_ANY', 'INADDR_BROADCAST', 'INADDR_LOOPBACK',
        'INADDR_MAX_LOCAL_GROUP', 'INADDR_NONE', 'INADDR_UNSPEC_GROUP', 'IOCTL_VM_SOCKETS_GET_LOCAL_CID', 'IPPORT_RESERVED', 'IPPORT_USERRESERVED',
        'IPPROTO_AH', 'IPPROTO_DSTOPTS', 'IPPROTO_EGP', 'IPPROTO_ESP', 'IPPROTO_FRAGMENT', 'IPPROTO_GRE',
        'IPPROTO_HOPOPTS', 'IPPROTO_ICMP', 'IPPROTO_ICMPV6', 'IPPROTO_IDP', 'IPPROTO_IGMP', 'IPPROTO_IP',
        'IPPROTO_IPIP', 'IPPROTO_IPV6', 'IPPROTO_MPTCP', 'IPPROTO_NONE', 'IPPROTO_PIM', 'IPPROTO_PUP',
        'IPPROTO_RAW', 'IPPROTO_ROUTING', 'IPPROTO_RSVP', 'IPPROTO_SCTP', 'IPPROTO_TCP', 'IPPROTO_TP',
        'IPPROTO_UDP', 'IPPROTO_UDPLITE', 'IPV6_CHECKSUM', 'IPV6_DONTFRAG', 'IPV6_DSTOPTS', 'IPV6_HOPLIMIT',
        'IPV6_HOPOPTS', 'IPV6_JOIN_GROUP', 'IPV6_LEAVE_GROUP', 'IPV6_MULTICAST_HOPS', 'IPV6_MULTICAST_IF', 'IPV6_MULTICAST_LOOP',
        'IPV6_NEXTHOP', 'IPV6_PATHMTU', 'IPV6_PKTINFO', 'IPV6_RECVDSTOPTS', 'IPV6_RECVHOPLIMIT', 'IPV6_RECVHOPOPTS',
        'IPV6_RECVPATHMTU', 'IPV6_RECVPKTINFO', 'IPV6_RECVRTHDR', 'IPV6_RECVTCLASS', 'IPV6_RTHDR', 'IPV6_RTHDRDSTOPTS',
        'IPV6_RTHDR_TYPE_0', 'IPV6_TCLASS', 'IPV6_UNICAST_HOPS', 'IPV6_V6ONLY', 'IP_ADD_MEMBERSHIP', 'IP_BIND_ADDRESS_NO_PORT',
        'IP_DEFAULT_MULTICAST_LOOP', 'IP_DEFAULT_MULTICAST_TTL', 'IP_DROP_MEMBERSHIP', 'IP_HDRINCL', 'IP_MAX_MEMBERSHIPS', 'IP_MULTICAST_IF',
        'IP_MULTICAST_LOOP', 'IP_MULTICAST_TTL', 'IP_OPTIONS', 'IP_RECVOPTS', 'IP_RECVRETOPTS', 'IP_RECVTOS',
        'IP_RETOPTS', 'IP_TOS', 'IP_TRANSPARENT', 'IP_TTL', 'J1939_EE_INFO_NONE', 'J1939_EE_INFO_TX_ABORT',
        'J1939_FILTER_MAX', 'J1939_IDLE_ADDR', 'J1939_MAX_UNICAST_ADDR', 'J1939_NLA_BYTES_ACKED', 'J1939_NLA_PAD', 'J1939_NO_ADDR',
        'J1939_NO_NAME', 'J1939_NO_PGN', 'J1939_PGN_ADDRESS_CLAIMED', 'J1939_PGN_ADDRESS_COMMANDED', 'J1939_PGN_MAX', 'J1939_PGN_PDU1_MAX',
        'J1939_PGN_REQUEST', 'NETLINK_CRYPTO', 'NETLINK_DNRTMSG', 'NETLINK_FIREWALL', 'NETLINK_IP6_FW', 'NETLINK_NFLOG',
        'NETLINK_ROUTE', 'NETLINK_USERSOCK', 'NETLINK_XFRM', 'NI_DGRAM', 'NI_MAXHOST', 'NI_MAXSERV',
        'NI_NAMEREQD', 'NI_NOFQDN', 'NI_NUMERICHOST', 'NI_NUMERICSERV', 'PACKET_BROADCAST', 'PACKET_FASTROUTE',
        'PACKET_HOST', 'PACKET_LOOPBACK', 'PACKET_MULTICAST', 'PACKET_OTHERHOST', 'PACKET_OUTGOING', 'PF_CAN',
        'PF_PACKET', 'PF_RDS', 'SCM_CREDENTIALS', 'SCM_J1939_DEST_ADDR', 'SCM_J1939_DEST_NAME', 'SCM_J1939_ERRQUEUE',
        'SCM_J1939_PRIO', 'SCM_RIGHTS', 'SHUT_RD', 'SHUT_RDWR', 'SHUT_WR', 'SOL_ALG',
        'SOL_CAN_BASE', 'SOL_CAN_RAW', 'SOL_HCI', 'SOL_IP', 'SOL_RDS', 'SOL_SOCKET',
        'SOL_TCP', 'SOL_TIPC', 'SOL_UDP', 'SOMAXCONN', 'SO_ACCEPTCONN', 'SO_BINDTODEVICE',
        'SO_BROADCAST', 'SO_DEBUG', 'SO_DOMAIN', 'SO_DONTROUTE', 'SO_ERROR', 'SO_INCOMING_CPU',
        'SO_J1939_ERRQUEUE', 'SO_J1939_FILTER', 'SO_J1939_PROMISC', 'SO_J1939_SEND_PRIO', 'SO_KEEPALIVE', 'SO_LINGER',
        'SO_MARK', 'SO_OOBINLINE', 'SO_PASSCRED', 'SO_PASSSEC', 'SO_PEERCRED', 'SO_PEERSEC',
        'SO_PRIORITY', 'SO_PROTOCOL', 'SO_RCVBUF', 'SO_RCVLOWAT', 'SO_RCVTIMEO', 'SO_REUSEADDR',
        'SO_REUSEPORT', 'SO_SNDBUF', 'SO_SNDLOWAT', 'SO_SNDTIMEO', 'SO_TYPE', 'SO_VM_SOCKETS_BUFFER_MAX_SIZE',
        'SO_VM_SOCKETS_BUFFER_MIN_SIZE', 'SO_VM_SOCKETS_BUFFER_SIZE', 'SocketType', 'TCP_CONGESTION', 'TCP_CORK', 'TCP_DEFER_ACCEPT',
        'TCP_FASTOPEN', 'TCP_INFO', 'TCP_KEEPCNT', 'TCP_KEEPIDLE', 'TCP_KEEPINTVL', 'TCP_LINGER2',
        'TCP_MAXSEG', 'TCP_NODELAY', 'TCP_NOTSENT_LOWAT', 'TCP_QUICKACK', 'TCP_SYNCNT', 'TCP_USER_TIMEOUT',
        'TCP_WINDOW_CLAMP', 'TIPC_ADDR_ID', 'TIPC_ADDR_NAME', 'TIPC_ADDR_NAMESEQ', 'TIPC_CFG_SRV', 'TIPC_CLUSTER_SCOPE',
        'TIPC_CONN_TIMEOUT', 'TIPC_CRITICAL_IMPORTANCE', 'TIPC_DEST_DROPPABLE', 'TIPC_HIGH_IMPORTANCE', 'TIPC_IMPORTANCE', 'TIPC_LOW_IMPORTANCE',
        'TIPC_MEDIUM_IMPORTANCE', 'TIPC_NODE_SCOPE', 'TIPC_PUBLISHED', 'TIPC_SRC_DROPPABLE', 'TIPC_SUBSCR_TIMEOUT', 'TIPC_SUB_CANCEL',
        'TIPC_SUB_PORTS', 'TIPC_SUB_SERVICE', 'TIPC_TOP_SRV', 'TIPC_WAIT_FOREVER', 'TIPC_WITHDRAWN', 'TIPC_ZONE_SCOPE',
        'UDPLITE_RECV_CSCOV', 'UDPLITE_SEND_CSCOV', 'VMADDR_CID_ANY', 'VMADDR_CID_HOST', 'VMADDR_PORT_ANY', 'VM_SOCKETS_INVALID_VERSION',
        'close', 'dup', 'error', 'gaierror', 'getdefaulttimeout', 'gethostbyaddr',
        'gethostbyname', 'gethostbyname_ex', 'gethostname', 'getnameinfo', 'getprotobyname', 'getservbyname',
        'getservbyport', 'has_ipv6', 'herror', 'htonl', 'htons', 'if_indextoname',
        'if_nameindex', 'if_nametoindex', 'inet_aton', 'inet_ntoa', 'inet_ntop', 'inet_pton',
        'ntohl', 'ntohs', 'setdefaulttimeout', 'sethostname', 'timeout',
    }),
    '_ssl': frozenset({
        'HAS_ALPN', 'HAS_ECDH', 'HAS_NPN', 'HAS_SNI', 'HAS_SSLv2', 'HAS_SSLv3',
        'HAS_TLSv1', 'HAS_TLSv1_1', 'HAS_TLSv1_2', 'HAS_TLSv1_3', 'MemoryBIO', 'OPENSSL_VERSION',
        'OPENSSL_VERSION_INFO', 'OPENSSL_VERSION_NUMBER', 'RAND_add', 'RAND_bytes', 'RAND_pseudo_bytes', 'RAND_status',
        'SSLCertVerificationError', 'SSLEOFError', 'SSLError', 'SSLSession', 'SSLSyscallError', 'SSLWantReadError',
        'SSLWantWriteError', 'SSLZeroReturnError', '_DEFAULT_CIPHERS', '_OPENSSL_API_VERSION', '_SSLContext',
    }),
    '_statistics': frozenset({
        '_normal_dist_inv_cdf',
    }),
    '_struct': frozenset({
        'Struct', '_clearcache', 'calcsize', 'error', 'iter_unpack', 'pack',
        'pack_into', 'unpack', 'unpack_from',
    }),
    '_warnings': frozenset({
        '_defaultaction', '_filters_mutated', '_onceregistry', 'filters', 'warn', 'warn_explicit',
    }),
    '_weakref': frozenset({
        'CallableProxyType', 'ProxyType', 'ReferenceType', '_remove_dead_weakref', 'getweakrefcount', 'getweakrefs',
        'proxy', 'ref',
    }),
    'posix': frozenset({
        'CLD_CONTINUED', 'CLD_DUMPED', 'CLD_EXITED', 'CLD_KILLED', 'CLD_STOPPED', 'CLD_TRAPPED',
        'DirEntry', 'EFD_CLOEXEC', 'EFD_NONBLOCK', 'EFD_SEMAPHORE', 'EX_CANTCREAT', 'EX_CONFIG',
        'EX_DATAERR', 'EX_IOERR', 'EX_NOHOST', 'EX_NOINPUT', 'EX_NOPERM', 'EX_NOUSER',
        'EX_OK', 'EX_OSERR', 'EX_OSFILE', 'EX_PROTOCOL', 'EX_SOFTWARE', 'EX_TEMPFAIL',
        'EX_UNAVAILABLE', 'EX_USAGE', 'F_LOCK', 'F_OK', 'F_TEST', 'F_TLOCK',
        'F_ULOCK', 'GRND_NONBLOCK', 'GRND_RANDOM', 'MFD_ALLOW_SEALING', 'MFD_CLOEXEC', 'MFD_HUGETLB',
        'MFD_HUGE_16GB', 'MFD_HUGE_16MB', 'MFD_HUGE_1GB', 'MFD_HUGE_1MB', 'MFD_HUGE_256MB', 'MFD_HUGE_2GB',
        'MFD_HUGE_2MB', 'MFD_HUGE_32MB', 'MFD_HUGE_512KB', 'MFD_HUGE_512MB', 'MFD_HUGE_64KB', 'MFD_HUGE_8MB',
        'MFD_HUGE_MASK', 'MFD_HUGE_SHIFT', 'NGROUPS_MAX', 'O_ACCMODE', 'O_APPEND', 'O_ASYNC',
        'O_CLOEXEC', 'O_CREAT', 'O_DIRECT', 'O_DIRECTORY', 'O_DSYNC', 'O_EXCL',
        'O_FSYNC', 'O_LARGEFILE', 'O_NDELAY', 'O_NOATIME', 'O_NOCTTY', 'O_NOFOLLOW',
        'O_NONBLOCK', 'O_PATH', 'O_RDONLY', 'O_RDWR', 'O_RSYNC', 'O_SYNC',
        'O_TMPFILE', 'O_TRUNC', 'O_WRONLY', 'POSIX_FADV_DONTNEED', 'POSIX_FADV_NOREUSE', 'POSIX_FADV_NORMAL',
        'POSIX_FADV_RANDOM', 'POSIX_FADV_SEQUENTIAL', 'POSIX_FADV_WILLNEED', 'POSIX_SPAWN_CLOSE', 'POSIX_SPAWN_DUP2', 'POSIX_SPAWN_OPEN',
        'PRIO_PGRP', 'PRIO_PROCESS', 'PRIO_USER', 'P_ALL', 'P_PGID', 'P_PID',
        'P_PIDFD', 'RTLD_DEEPBIND', 'RTLD_GLOBAL', 'RTLD_LAZY', 'RTLD_LOCAL', 'RTLD_NODELETE',
        'RTLD_NOLOAD', 'RTLD_NOW', 'RWF_APPEND', 'RWF_DSYNC', 'RWF_HIPRI', 'RWF_NOWAIT',
        'RWF_SYNC', 'R_OK', 'SCHED_BATCH', 'SCHED_FIFO', 'SCHED_IDLE', 'SCHED_OTHER',
        'SCHED_RESET_ON_FORK', 'SCHED_RR', 'SEEK_DATA', 'SEEK_HOLE', 'SPLICE_F_MORE', 'SPLICE_F_MOVE',
        'SPLICE_F_NONBLOCK', 'ST_APPEND', 'ST_MANDLOCK', 'ST_NOATIME', 'ST_NODEV', 'ST_NODIRATIME',
        'ST_NOEXEC', 'ST_NOSUID', 'ST_RDONLY', 'ST_RELATIME', 'ST_SYNCHRONOUS', 'ST_WRITE',
        'TMP_MAX', 'WCONTINUED', 'WCOREDUMP', 'WEXITED', 'WEXITSTATUS', 'WIFCONTINUED',
        'WIFEXITED', 'WIFSIGNALED', 'WIFSTOPPED', 'WNOHANG', 'WNOWAIT', 'WSTOPPED',
        'WSTOPSIG', 'WTERMSIG', 'WUNTRACED', 'W_OK', 'XATTR_CREATE', 'XATTR_REPLACE',
        'XATTR_SIZE_MAX', 'X_OK', '_exit', 'abort', 'access', 'chdir',
        'chmod', 'chown', 'chroot', 'close', 'closerange', 'confstr',
        'confstr_names', 'copy_file_range', 'cpu_count', 'ctermid', 'device_encoding', 'dup',
        'dup2', 'error', 'eventfd', 'eventfd_read', 'eventfd_write', 'execv',
        'execve', 'fchdir', 'fchmod', 'fchown', 'fdatasync', 'fork',
        'forkpty', 'fpathconf', 'fspath', 'fstat', 'fstatvfs', 'fsync',
        'ftruncate', 'get_blocking', 'get_inheritable', 'get_terminal_size', 'getcwd', 'getcwdb',
        'getegid', 'geteuid', 'getgid', 'getgrouplist', 'getgroups', 'getloadavg',
        'getlogin', 'getpgid', 'getpgrp', 'getpid', 'getppid', 'getpriority',
        'getrandom', 'getresgid', 'getresuid', 'getsid', 'getuid', 'getxattr',
        'initgroups', 'isatty', 'kill', 'killpg', 'lchown', 'link',
        'listdir', 'listxattr', 'lockf', 'login_tty', 'lseek', 'lstat',
        'major', 'makedev', 'memfd_create', 'minor', 'mkdir', 'mkfifo',
        'mknod', 'nice', 'open', 'openpty', 'pathconf', 'pathconf_names',
        'pidfd_open', 'pipe', 'pipe2', 'posix_fadvise', 'posix_fallocate', 'posix_spawn',
        'posix_spawnp', 'pread', 'preadv', 'putenv', 'pwrite', 'pwritev',
        'read', 'readlink', 'readv', 'register_at_fork', 'remove', 'removexattr',
        'rename', 'replace', 'rmdir', 'scandir', 'sched_get_priority_max', 'sched_get_priority_min',
        'sched_getaffinity', 'sched_getparam', 'sched_getscheduler', 'sched_param', 'sched_rr_get_interval', 'sched_setaffinity',
        'sched_setparam', 'sched_setscheduler', 'sched_yield', 'sendfile', 'set_blocking', 'set_inheritable',
        'setegid', 'seteuid', 'setgid', 'setgroups', 'setpgid', 'setpgrp',
        'setpriority', 'setregid', 'setresgid', 'setresuid', 'setreuid', 'setsid',
        'setuid', 'setxattr', 'splice', 'stat', 'stat_result', 'statvfs',
        'statvfs_result', 'strerror', 'symlink', 'sync', 'sysconf', 'sysconf_names',
        'system', 'tcgetpgrp', 'tcsetpgrp', 'terminal_size', 'times', 'times_result',
        'truncate', 'ttyname', 'umask', 'uname', 'uname_result', 'unlink',
        'unsetenv', 'urandom', 'utime', 'wait', 'wait3', 'wait4',
        'waitid', 'waitid_result', 'waitpid', 'waitstatus_to_exitcode', 'write', 'writev',
    }),
}


# ──────────────────────────────────────────────────────────────────────────
# Canonicalization
# ──────────────────────────────────────────────────────────────────────────
def split_qualname(qual: str) -> Tuple[str, str]:
    if not isinstance(qual, str) or "." not in qual:
        return "", qual or ""
    mod, _, name = qual.rpartition(".")
    return mod, name


class CanonResult(object):
    __slots__ = ("module", "name", "raw_module", "raw_name",
                 "steps", "unresolvable", "protocol")

    def __init__(self, module: str, name: str, raw_module: str, raw_name: str,
                 steps, unresolvable: bool, protocol: int):
        self.module = module
        self.name = name
        self.raw_module = raw_module
        self.raw_name = raw_name
        self.steps = steps
        self.unresolvable = unresolvable
        self.protocol = protocol

    @property
    def canonical(self) -> str:
        return "%s.%s" % (self.module, self.name) if self.module else self.name

    @property
    def raw(self) -> str:
        return ("%s.%s" % (self.raw_module, self.raw_name)
                if self.raw_module else self.raw_name)

    @property
    def changed(self) -> bool:
        return (self.module, self.name) != (self.raw_module, self.raw_name)

    def __repr__(self) -> str:                            # pragma: no cover
        return "CanonResult(%s <- %s, proto=%s)" % (self.canonical, self.raw, self.protocol)


def canon(module: Optional[str], name: Optional[str], protocol: int = 0,
          *, fix_imports: bool = True) -> CanonResult:
    """Internal implementation detail."""
    raw_mod = module or ""
    raw_name = name or ""
    mod, nm = raw_mod, raw_name
    steps = []
    unresolvable = False

    # Step 1 -- compatibility remapping (protocol < 3 only)
    if protocol < 3 and fix_imports:
        if (mod, nm) in NAME_MAPPING:
            mod, nm = NAME_MAPPING[(mod, nm)]
            steps.append("compat_name")
        elif mod in IMPORT_MAPPING:
            mod = IMPORT_MAPPING[mod]
            steps.append("compat_import")
    elif mod in IMPORT_MAPPING or (mod, nm) in NAME_MAPPING:
        # A py2-only name under protocol >= 3 cannot be resolved by the loader.
        unresolvable = True

    # Step 2 -- alias folding (identity-verified pairs only)
    target = MODULE_ALIAS.get(mod)
    if target and nm in NAME_ALIAS.get(mod, ()):
        mod = target
        steps.append("object_alias")

    return CanonResult(mod, nm, raw_mod, raw_name, tuple(steps), unresolvable, protocol)
