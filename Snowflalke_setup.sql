use role accountadmin;

create database APPS; 
create schema APPS.DATA;

use database APPS; 
use schema APPS.DATA;

create stage if not exists
STG_STREAMLIT
ENCRYPTION = (  TYPE = 'SNOWFLAKE_SSE' ) ;




PUT file:////Users/rpegu/Documents/Snowflake/StreamlitApps/Snowflake_Security_Ninja/app.py @APPS.DATA.STG_STREAMLIT overwrite=true auto_compress=false;

put file:////Users/rpegu/Documents/Snowflake/StreamlitApps/Snowflake_Security_Ninja/environment.yml @APPS.DATA.STG_STREAMLIT overwrite=true auto_compress=false;


use database APPS; 
use schema APPS.DATA;


CREATE STREAMLIT Security_Ninja_App
ROOT_LOCATION = '@APPS.DATA.STG_STREAMLIT '
MAIN_FILE = 'app.py'
QUERY_WAREHOUSE = 'ML_FS_W';