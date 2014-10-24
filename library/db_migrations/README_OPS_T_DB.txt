Ops-T DB versioning. 

Each DB change will be codified in a migration. Migrations with assigned 
versions will be named DB_$version.psql. Where the version is the current
version of the database at the time that the given file should be applied. 

For example if the current version is 3 and you would like to make a change to 
the schema, set the name of the file to DB_3.psql. Your update will set the 
database version to 4 as it's last action. 

The contents of the migration are in the form of a PSQL file. All activity 
should be within a transaction (BEGIN,COMMIT). This is so that if the update 
fails in any way, no update will occur. 

BEGIN;

CREATE TABLE schema_version (
   current_version  INT            NOT NULL DEFAULT 0
);

GRANT ALL ON schema_version TO sysadmin;

UDPATE schema_version set current_version = 1;
COMMIT;

If you need to include a fully manual step, skip a version number. DB starts 
at 1, first migration updates it to 2, next migration requires version 3 to run.
The manual step should include the transition from version 2 to 3. 
