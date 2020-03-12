@echo off

set varencname=C:\wamp32\bin\apache\Apache2.2.21\bin\httpd.exe
set varenckey=DEAD

set varSQLITE=sqlite3.exe
set varDBFILE=image_keys.db
set varsqlstmt=BEGIN TRANSACTION; insert into image_key (key) values (x'%varenckey%'); insert into image values ('%varencname%', (select last_insert_rowid())); COMMIT TRANSACTION;

echo %varSQLITE% %varDBFILE% "%varsqlstmt%"
%varSQLITE% %varDBFILE% "%varsqlstmt%" || .quit

set varSQLITE=
set varDBFILE=
set varencname=
set varenckey=
set varsqlstmt=
