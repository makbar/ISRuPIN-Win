/**
 * Muhammad Ali Akbar
 * maa2206@columbia.edu
 * Columbia University, NY
 *
 * For queries: ali.akbar.ceme@gmail.com
 *
 */

About:
This is the sqlite database for storing the encryption keys. The sqlite3 client,
the database structure (sql) file, the database (db) file, and a script to
insert keys in to the database are attached.

Pre-requisites:
sqlite3.exe (included in the database folder).

Usage:
Change the varenckey and varencname parameters to the required key and executable path
in the insert_key_to_db.bat file, and run it to insert the key in the image.

You can browse the database using the sqlite3 client by:
sqlite3.exe image_keys.db
