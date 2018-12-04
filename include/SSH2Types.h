/**************************************************************************
*   Copyright (C) 2008-2009 by Paul Thomas thomaspu@gmail.com
*   All rights reserved.
*
*   This file is part of PTssh
*
*   Permission to use, copy, modify, and distribute this software for any purpose
*   with or without fee is hereby granted, provided that the above copyright
*   notice and this permission notice appear in all copies.
*
*   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN
*   NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
*   DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
*   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
*   OR OTHER DEALINGS IN THE SOFTWARE.
*
*   Except as contained in this notice, the name of a copyright holder shall not
*   be used in advertising or otherwise to promote the sale, use or other dealings
*   in this Software without prior written authorization of the copyright holder.
*************************************************************************/

#ifndef _SSH2TYPES
#define _SSH2TYPES

/**
* This file holds all SSH2 types as defined in the appropriate RFCs:
 rfc4250.txt
 rfc4251.txt
 rfc4252.txt
 rfc4253.txt
 rfc4254.txt
*/



#define SSH_MSG_DISCONNECT                       1
#define SSH_MSG_IGNORE                           2
#define SSH_MSG_UNIMPLEMENTED                    3
#define SSH_MSG_DEBUG                            4
#define SSH_MSG_SERVICE_REQUEST                  5
#define SSH_MSG_SERVICE_ACCEPT                   6
#define SSH_MSG_KEXINIT                         20
#define SSH_MSG_NEWKEYS                         21
#define SSH_MSG_KEXDH_INIT                      30
#define SSH_MSG_KEXDH_REPLY                     31
#define SSH_MSG_USERAUTH_REQUEST                50
#define SSH_MSG_USERAUTH_FAILURE                51
#define SSH_MSG_USERAUTH_SUCCESS                52
#define SSH_MSG_USERAUTH_BANNER                 53
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ		60
#define SSH_MSG_GLOBAL_REQUEST                  80
#define SSH_MSG_REQUEST_SUCCESS                 81
#define SSH_MSG_REQUEST_FAILURE                 82
#define SSH_MSG_CHANNEL_OPEN                    90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION       91
#define SSH_MSG_CHANNEL_OPEN_FAILURE            92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST           93
#define SSH_MSG_CHANNEL_DATA                    94  //0x5E
#define SSH_MSG_CHANNEL_EXTENDED_DATA           95
#define SSH_MSG_CHANNEL_EOF                     96
#define SSH_MSG_CHANNEL_CLOSE                   97
#define SSH_MSG_CHANNEL_REQUEST                 98
#define SSH_MSG_CHANNEL_SUCCESS                 99
#define SSH_MSG_CHANNEL_FAILURE                100

/* SSH Public key related */
#define SSH_MSG_USERAUTH_PK_OK 60



/* Disconnect descriptions */
#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT          1
#define SSH_DISCONNECT_PROTOCOL_ERROR                       2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED                  3
#define SSH_DISCONNECT_RESERVED                             4
#define SSH_DISCONNECT_MAC_ERROR                            5
#define SSH_DISCONNECT_COMPRESSION_ERROR                    6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE                7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED       8
#define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE              9
#define SSH_DISCONNECT_CONNECTION_LOST                     10
#define SSH_DISCONNECT_BY_APPLICATION                      11
#define SSH_DISCONNECT_TOO_MANY_CONNECTIONS                12
#define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER              13
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE      14
#define SSH_DISCONNECT_ILLEGAL_USER_NAME                   15

/* Reason codes */
#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED                1
#define SSH_OPEN_CONNECT_FAILED                             2
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE                       3
#define SSH_OPEN_RESOURCE_SHORTAGE                          4

/* Datatype error */
#define SSH_EXTENDED_DATA_STDERR       1


/***************************
* SSH SFTP data types
***************************/
#ifdef PTSSH_SFTP
#define SSH_FXP_INIT                1
#define SSH_FXP_VERSION             2
#define SSH_FXP_OPEN                3
#define SSH_FXP_CLOSE               4
#define SSH_FXP_READ                5
#define SSH_FXP_WRITE               6
#define SSH_FXP_LSTAT               7
#define SSH_FXP_FSTAT               8
#define SSH_FXP_SETSTAT             9
#define SSH_FXP_FSETSTAT           10
#define SSH_FXP_OPENDIR            11
#define SSH_FXP_READDIR            12
#define SSH_FXP_REMOVE             13
#define SSH_FXP_MKDIR              14
#define SSH_FXP_RMDIR              15
#define SSH_FXP_REALPATH           16
#define SSH_FXP_STAT               17
#define SSH_FXP_RENAME             18
#define SSH_FXP_READLINK           19
#define SSH_FXP_SYMLINK            20
#define SSH_FXP_LINK               21
#define SSH_FXP_BLOCK              22
#define SSH_FXP_UNBLOCK            23

#define SSH_FXP_STATUS            101  //0x65
#define SSH_FXP_HANDLE            102  //0x66
#define SSH_FXP_DATA              103  //0x67
#define SSH_FXP_NAME              104  //0x68
#define SSH_FXP_ATTRS             105  //0x69

#define SSH_FXP_EXTENDED          200
#define SSH_FXP_EXTENDED_REPLY    201




#define SSH_FXF_READ            0x00000001
#define SSH_FXF_WRITE           0x00000002
#define SSH_FXF_APPEND          0x00000004
#define SSH_FXF_CREAT           0x00000008
#define SSH_FXF_TRUNC           0x00000010
#define SSH_FXF_EXCL            0x00000020

// File attribute flags SFTP ver 3
#define SSH_FILEXFER_ATTR_SIZE          0x00000001
#define SSH_FILEXFER_ATTR_UIDGID        0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS   0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME     0x00000008  /* v3 only */

#define SSH_FILEXFER_ATTR_EXTENDED      0x80000000

// File attribute flags SFTP ver 6
#define SSH_FILEXFER_ATTR_SIZE              0x00000001
#define SSH_FILEXFER_ATTR_PERMISSIONS       0x00000004
#define SSH_FILEXFER_ATTR_ACCESSTIME        0x00000008
#define SSH_FILEXFER_ATTR_CREATETIME        0x00000010
#define SSH_FILEXFER_ATTR_MODIFYTIME        0x00000020
#define SSH_FILEXFER_ATTR_ACL               0x00000040
#define SSH_FILEXFER_ATTR_OWNERGROUP        0x00000080
#define SSH_FILEXFER_ATTR_SUBSECOND_TIMES   0x00000100
#define SSH_FILEXFER_ATTR_BITS              0x00000200
#define SSH_FILEXFER_ATTR_ALLOCATION_SIZE   0x00000400
#define SSH_FILEXFER_ATTR_TEXT_HINT         0x00000800
#define SSH_FILEXFER_ATTR_MIME_TYPE         0x00001000
#define SSH_FILEXFER_ATTR_LINK_COUNT        0x00002000
#define SSH_FILEXFER_ATTR_UNTRANSLATED_NAME 0x00004000
#define SSH_FILEXFER_ATTR_CTIME             0x00008000
#define SSH_FILEXFER_ATTR_EXTENDED          0x80000000

//File types
#define SSH_FILEXFER_TYPE_REGULAR          1
#define SSH_FILEXFER_TYPE_DIRECTORY        2
#define SSH_FILEXFER_TYPE_SYMLINK          3
#define SSH_FILEXFER_TYPE_SPECIAL          4
#define SSH_FILEXFER_TYPE_UNKNOWN          5
#define SSH_FILEXFER_TYPE_SOCKET           6
#define SSH_FILEXFER_TYPE_CHAR_DEVICE      7
#define SSH_FILEXFER_TYPE_BLOCK_DEVICE     8
#define SSH_FILEXFER_TYPE_FIFO             9

//SSH SSH_FXP_STATUS error/status codes
#define SSH_FX_OK                            0
#define SSH_FX_EOF                           1
#define SSH_FX_NO_SUCH_FILE                  2
#define SSH_FX_PERMISSION_DENIED             3
#define SSH_FX_FAILURE                       4
#define SSH_FX_BAD_MESSAGE                   5
#define SSH_FX_NO_CONNECTION                 6
#define SSH_FX_CONNECTION_LOST               7
#define SSH_FX_OP_UNSUPPORTED                8



#endif

#endif