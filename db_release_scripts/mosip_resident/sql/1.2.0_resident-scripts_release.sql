-- -------------------------------------------------------------------------------------------------
-- Database Name: mosip_resident
-- Release Version 	: 1.2.1
-- Purpose    		: Database scripts for Resident Service DB.       
-- Create By   		: Manoj SP
-- Created Date		: April-2022
-- 
-- Modified Date        Modified By             Comments / Remarks
-- --------------------------------------------------------------------------------------------------
-- April-2022			Manoj SP	            Added otp_transaction table creation scripts with comments.
-- April-2022           Kamesh Shekhar Prasad   Added resident_transaction table creation scripts with comments.
-- May-2022				Kamesh Shekhar Prasad   Added auth_transaction table creation scripts with comments.
-----------------------------------------------------------------------------------------------------
\c mosip_resident sysadmin

\ir ddl/otp_transaction.sql
\ir ddl/resident_transaction.sql
\ir ddl/auth_transaction.sql
-----------------------------------------------------------------------------------------------------