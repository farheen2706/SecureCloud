PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "django_migrations" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "app" varchar(255) NOT NULL, "name" varchar(255) NOT NULL, "applied" datetime NOT NULL);
INSERT INTO django_migrations VALUES(1,'contenttypes','0001_initial','2025-03-29 11:07:37.464886');
INSERT INTO django_migrations VALUES(2,'auth','0001_initial','2025-03-29 11:07:37.517866');
INSERT INTO django_migrations VALUES(3,'admin','0001_initial','2025-03-29 11:07:37.571807');
INSERT INTO django_migrations VALUES(4,'admin','0002_logentry_remove_auto_add','2025-03-29 11:07:37.597530');
INSERT INTO django_migrations VALUES(5,'admin','0003_logentry_add_action_flag_choices','2025-03-29 11:07:37.619843');
INSERT INTO django_migrations VALUES(6,'contenttypes','0002_remove_content_type_name','2025-03-29 11:07:37.645403');
INSERT INTO django_migrations VALUES(7,'auth','0002_alter_permission_name_max_length','2025-03-29 11:07:37.667024');
INSERT INTO django_migrations VALUES(8,'auth','0003_alter_user_email_max_length','2025-03-29 11:07:37.688037');
INSERT INTO django_migrations VALUES(9,'auth','0004_alter_user_username_opts','2025-03-29 11:07:37.707796');
INSERT INTO django_migrations VALUES(10,'auth','0005_alter_user_last_login_null','2025-03-29 11:07:37.727681');
INSERT INTO django_migrations VALUES(11,'auth','0006_require_contenttypes_0002','2025-03-29 11:07:37.740111');
INSERT INTO django_migrations VALUES(12,'auth','0007_alter_validators_add_error_messages','2025-03-29 11:07:37.756401');
INSERT INTO django_migrations VALUES(13,'auth','0008_alter_user_username_max_length','2025-03-29 11:07:37.775489');
INSERT INTO django_migrations VALUES(14,'auth','0009_alter_user_last_name_max_length','2025-03-29 11:07:37.798840');
INSERT INTO django_migrations VALUES(15,'auth','0010_alter_group_name_max_length','2025-03-29 11:07:37.820152');
INSERT INTO django_migrations VALUES(16,'auth','0011_update_proxy_permissions','2025-03-29 11:07:37.838477');
INSERT INTO django_migrations VALUES(17,'auth','0012_alter_user_first_name_max_length','2025-03-29 11:07:37.858038');
INSERT INTO django_migrations VALUES(18,'files','0001_initial','2025-03-29 11:07:37.902072');
INSERT INTO django_migrations VALUES(19,'sessions','0001_initial','2025-03-29 11:07:37.927128');
INSERT INTO django_migrations VALUES(20,'files','0002_alter_employee_password','2025-03-29 11:24:06.447010');
CREATE TABLE IF NOT EXISTS "auth_group_permissions" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "group_id" integer NOT NULL REFERENCES "auth_group" ("id") DEFERRABLE INITIALLY DEFERRED, "permission_id" integer NOT NULL REFERENCES "auth_permission" ("id") DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE IF NOT EXISTS "auth_user_groups" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "user_id" integer NOT NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED, "group_id" integer NOT NULL REFERENCES "auth_group" ("id") DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE IF NOT EXISTS "auth_user_user_permissions" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "user_id" integer NOT NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED, "permission_id" integer NOT NULL REFERENCES "auth_permission" ("id") DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE IF NOT EXISTS "django_admin_log" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "object_id" text NULL, "object_repr" varchar(200) NOT NULL, "action_flag" smallint unsigned NOT NULL CHECK ("action_flag" >= 0), "change_message" text NOT NULL, "content_type_id" integer NULL REFERENCES "django_content_type" ("id") DEFERRABLE INITIALLY DEFERRED, "user_id" integer NOT NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED, "action_time" datetime NOT NULL);
CREATE TABLE IF NOT EXISTS "django_content_type" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "app_label" varchar(100) NOT NULL, "model" varchar(100) NOT NULL);
INSERT INTO django_content_type VALUES(1,'files','employee');
INSERT INTO django_content_type VALUES(2,'files','log');
INSERT INTO django_content_type VALUES(3,'files','medicine');
INSERT INTO django_content_type VALUES(4,'files','component');
INSERT INTO django_content_type VALUES(5,'admin','logentry');
INSERT INTO django_content_type VALUES(6,'auth','permission');
INSERT INTO django_content_type VALUES(7,'auth','group');
INSERT INTO django_content_type VALUES(8,'auth','user');
INSERT INTO django_content_type VALUES(9,'contenttypes','contenttype');
INSERT INTO django_content_type VALUES(10,'sessions','session');
CREATE TABLE IF NOT EXISTS "auth_permission" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "content_type_id" integer NOT NULL REFERENCES "django_content_type" ("id") DEFERRABLE INITIALLY DEFERRED, "codename" varchar(100) NOT NULL, "name" varchar(255) NOT NULL);
INSERT INTO auth_permission VALUES(1,1,'add_employee','Can add employee');
INSERT INTO auth_permission VALUES(2,1,'change_employee','Can change employee');
INSERT INTO auth_permission VALUES(3,1,'delete_employee','Can delete employee');
INSERT INTO auth_permission VALUES(4,1,'view_employee','Can view employee');
INSERT INTO auth_permission VALUES(5,2,'add_log','Can add log');
INSERT INTO auth_permission VALUES(6,2,'change_log','Can change log');
INSERT INTO auth_permission VALUES(7,2,'delete_log','Can delete log');
INSERT INTO auth_permission VALUES(8,2,'view_log','Can view log');
INSERT INTO auth_permission VALUES(9,3,'add_medicine','Can add medicine');
INSERT INTO auth_permission VALUES(10,3,'change_medicine','Can change medicine');
INSERT INTO auth_permission VALUES(11,3,'delete_medicine','Can delete medicine');
INSERT INTO auth_permission VALUES(12,3,'view_medicine','Can view medicine');
INSERT INTO auth_permission VALUES(13,4,'add_component','Can add component');
INSERT INTO auth_permission VALUES(14,4,'change_component','Can change component');
INSERT INTO auth_permission VALUES(15,4,'delete_component','Can delete component');
INSERT INTO auth_permission VALUES(16,4,'view_component','Can view component');
INSERT INTO auth_permission VALUES(17,5,'add_logentry','Can add log entry');
INSERT INTO auth_permission VALUES(18,5,'change_logentry','Can change log entry');
INSERT INTO auth_permission VALUES(19,5,'delete_logentry','Can delete log entry');
INSERT INTO auth_permission VALUES(20,5,'view_logentry','Can view log entry');
INSERT INTO auth_permission VALUES(21,6,'add_permission','Can add permission');
INSERT INTO auth_permission VALUES(22,6,'change_permission','Can change permission');
INSERT INTO auth_permission VALUES(23,6,'delete_permission','Can delete permission');
INSERT INTO auth_permission VALUES(24,6,'view_permission','Can view permission');
INSERT INTO auth_permission VALUES(25,7,'add_group','Can add group');
INSERT INTO auth_permission VALUES(26,7,'change_group','Can change group');
INSERT INTO auth_permission VALUES(27,7,'delete_group','Can delete group');
INSERT INTO auth_permission VALUES(28,7,'view_group','Can view group');
INSERT INTO auth_permission VALUES(29,8,'add_user','Can add user');
INSERT INTO auth_permission VALUES(30,8,'change_user','Can change user');
INSERT INTO auth_permission VALUES(31,8,'delete_user','Can delete user');
INSERT INTO auth_permission VALUES(32,8,'view_user','Can view user');
INSERT INTO auth_permission VALUES(33,9,'add_contenttype','Can add content type');
INSERT INTO auth_permission VALUES(34,9,'change_contenttype','Can change content type');
INSERT INTO auth_permission VALUES(35,9,'delete_contenttype','Can delete content type');
INSERT INTO auth_permission VALUES(36,9,'view_contenttype','Can view content type');
INSERT INTO auth_permission VALUES(37,10,'add_session','Can add session');
INSERT INTO auth_permission VALUES(38,10,'change_session','Can change session');
INSERT INTO auth_permission VALUES(39,10,'delete_session','Can delete session');
INSERT INTO auth_permission VALUES(40,10,'view_session','Can view session');
CREATE TABLE IF NOT EXISTS "auth_group" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(150) NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS "auth_user" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "password" varchar(128) NOT NULL, "last_login" datetime NULL, "is_superuser" bool NOT NULL, "username" varchar(150) NOT NULL UNIQUE, "last_name" varchar(150) NOT NULL, "email" varchar(254) NOT NULL, "is_staff" bool NOT NULL, "is_active" bool NOT NULL, "date_joined" datetime NOT NULL, "first_name" varchar(150) NOT NULL);
INSERT INTO auth_user VALUES(1,'pbkdf2_sha256$870000$IXS6QoLwBKPfV2lFhjAvsL$mjvapezLn2OwVhOuhaZ3poZiht4klJuR3Yv5wsJCIHo=',NULL,1,'farheen','','farheen.unom@gmail.com',1,1,'2025-03-29 11:08:23.745943','');
CREATE TABLE IF NOT EXISTS "files_log" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "created" datetime NOT NULL, "name" varchar(100) NOT NULL, "component_name" varchar(500) NOT NULL, "component_quantity" varchar(500) NOT NULL, "component_cost" varchar(500) NOT NULL);
CREATE TABLE IF NOT EXISTS "files_medicine" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "medicine_name" varchar(100) NOT NULL, "manager_id" integer NOT NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE IF NOT EXISTS "files_component" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "component_name" varchar(500) NOT NULL, "component_quantity" varchar(500) NOT NULL, "component_cost" varchar(500) NOT NULL, "key_id" bigint NOT NULL REFERENCES "files_medicine" ("id") DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE IF NOT EXISTS "django_session" ("session_key" varchar(40) NOT NULL PRIMARY KEY, "session_data" text NOT NULL, "expire_date" datetime NOT NULL);
CREATE TABLE IF NOT EXISTS "files_employee" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "email" varchar(100) NOT NULL UNIQUE, "name" varchar(100) NOT NULL, "manager_name" varchar(100) NOT NULL, "medicine_name" varchar(100) NOT NULL, "last_login" datetime NOT NULL, "password" varchar(128) NULL);
INSERT INTO sqlite_sequence VALUES('django_migrations',20);
INSERT INTO sqlite_sequence VALUES('django_admin_log',0);
INSERT INTO sqlite_sequence VALUES('django_content_type',10);
INSERT INTO sqlite_sequence VALUES('auth_permission',40);
INSERT INTO sqlite_sequence VALUES('auth_group',0);
INSERT INTO sqlite_sequence VALUES('auth_user',1);
INSERT INTO sqlite_sequence VALUES('files_employee',0);
CREATE UNIQUE INDEX "auth_group_permissions_group_id_permission_id_0cd325b0_uniq" ON "auth_group_permissions" ("group_id", "permission_id");
CREATE INDEX "auth_group_permissions_group_id_b120cbf9" ON "auth_group_permissions" ("group_id");
CREATE INDEX "auth_group_permissions_permission_id_84c5c92e" ON "auth_group_permissions" ("permission_id");
CREATE UNIQUE INDEX "auth_user_groups_user_id_group_id_94350c0c_uniq" ON "auth_user_groups" ("user_id", "group_id");
CREATE INDEX "auth_user_groups_user_id_6a12ed8b" ON "auth_user_groups" ("user_id");
CREATE INDEX "auth_user_groups_group_id_97559544" ON "auth_user_groups" ("group_id");
CREATE UNIQUE INDEX "auth_user_user_permissions_user_id_permission_id_14a6b632_uniq" ON "auth_user_user_permissions" ("user_id", "permission_id");
CREATE INDEX "auth_user_user_permissions_user_id_a95ead1b" ON "auth_user_user_permissions" ("user_id");
CREATE INDEX "auth_user_user_permissions_permission_id_1fbb5f2c" ON "auth_user_user_permissions" ("permission_id");
CREATE INDEX "django_admin_log_content_type_id_c4bce8eb" ON "django_admin_log" ("content_type_id");
CREATE INDEX "django_admin_log_user_id_c564eba6" ON "django_admin_log" ("user_id");
CREATE UNIQUE INDEX "django_content_type_app_label_model_76bd3d3b_uniq" ON "django_content_type" ("app_label", "model");
CREATE UNIQUE INDEX "auth_permission_content_type_id_codename_01ab375a_uniq" ON "auth_permission" ("content_type_id", "codename");
CREATE INDEX "auth_permission_content_type_id_2f476e4b" ON "auth_permission" ("content_type_id");
CREATE INDEX "files_medicine_manager_id_6335b755" ON "files_medicine" ("manager_id");
CREATE INDEX "files_component_key_id_6a40c17a" ON "files_component" ("key_id");
CREATE INDEX "django_session_expire_date_a5c62663" ON "django_session" ("expire_date");
COMMIT;
