
create table image_key (
	keyid INTEGER PRIMARY KEY AUTOINCREMENT,
	key BLOB,
	refs INTEGER DEFAULT 1
	);

create table image (
	path TEXT(2048) PRIMARY KEY NOT NULL,
	keyid INTEGER REFERENCES image_key(keyid)
	);


create trigger image_delete after delete on image
BEGIN
update image_key set refs=refs-1 where keyid=OLD.keyid;
END;


CREATE TRIGGER clean_unused_keys after update of refs on image_key when NEW.refs<=0
begin
delete from image_key where keyid=NEW.keyid;
end;
