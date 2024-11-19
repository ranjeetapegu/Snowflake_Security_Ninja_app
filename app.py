# Import python packages
import streamlit as st
from snowflake.snowpark.context import get_active_session
import plotly.express as px

# Write directly to the app
st.title("Security :ninja:")
st.write(
    """This a Security Dashboard App for governance.
    """
)

# Get the current credentials
session = get_active_session()
sql_text ="""select 
first_authentication_factor||' '||nvl(second_authentication_factor,'') as authentication_method,
count(*) as Number_of_Logins
from 
snowflake.account_usage.login_history
where is_success='YES'
and user_name !='WORKSHEETS_APP_USER'
group by authentication_method
order by  Number_of_Logins desc ;
"""
df =session.sql(sql_text).to_pandas()

st.subheader('Authentication Breakdown by Method')
fig = px.bar(df, y="AUTHENTICATION_METHOD", x="NUMBER_OF_LOGINS",color ="AUTHENTICATION_METHOD", orientation='h')
st.plotly_chart(fig, theme="streamlit", use_container_width=True)

st.subheader('Login Failure by Users and Reason')
sql_text ="""select 
user_name,
error_message,
count(*) num_of_failures 
from 
snowflake.account_usage.login_history
where 
is_success='NO'
group by user_name, error_message
order by  num_of_failures desc ;
"""
df =session.sql(sql_text).to_pandas()

fig = px.bar(df, x="USER_NAME", y="NUM_OF_FAILURES",color ="ERROR_MESSAGE")
st.plotly_chart(fig, theme="streamlit", use_container_width=True)




# Use an interactive slider to get user input
sql_text ="""
select 
name, 
datediff('day',password_last_set_time,current_timestamp())||' days ago'
as password_last_changed
from
snowflake.account_usage.users
where 
deleted_on is null and 
password_last_set_time is not null
order by password_last_set_time
"""


sql_text2 ="""
select 
u.name,
timediff(days,last_success_login,current_timestamp())||' days ago' last_login,
timediff(days,password_last_set_time, current_timestamp())||' days ago' password_age
from
snowflake.account_usage.users u
join snowflake.account_usage.grants_to_users g 
on grantee_name= name and role ='ACCOUNTADMIN'and g.deleted_on is null
where 
u.deleted_on is null and 
password_last_set_time is not null
order by last_success_login desc
"""

df1 = session.sql(sql_text).to_pandas()
df2 = session.sql(sql_text2).to_pandas()
# Execute the query and convert it into a Pandas dataframe
#st.write(df1,use_container_width=True)

st.header("Privileged Access")
col1, col2 = st.columns(2)


# Add a header to the first column
col1.write('Accountadmin Grants')
col1.write(df1)
# Add a header to the second column
col2.write('Accountadmin w/o MFA')
col2.write(df2)

st.header("Identity Management")
sql_text1 ="""
select 
u.name,
datediff('day',password_last_set_time,current_timestamp())||' days ago' as password_last_changed
from
snowflake.account_usage.users u
where 
u.deleted_on is null and 
password_last_set_time is not null
order by password_last_set_time desc
"""

sql_text2 ="""
select 
u.name,
datediff('day',nvl(last_success_login,created_on),current_timestamp())||' days ago' as last_Logins
from
snowflake.account_usage.users u
where 
u.deleted_on is null and 
password_last_set_time is not null
order by datediff('day',nvl(last_success_login,created_on),current_timestamp()) desc
"""
sql_text3 ="""
select 
user_name as by_whom,
datediff('day',start_time,current_timestamp())||' days ago' as created_on,
add_months(start_time,6) as expires_on,
datediff('day',
current_timestamp(),
ADD_MONTHS(end_time,6)) as expires_in_days
from
snowflake.account_usage.query_history
where 
execution_status = 'SUCCESS'
and  query_text ilike 'select%SYSTEM$GENERATE_SCIM_ACCESS_TOKEN%'
and  query_text not ilike 'select%where%SYSTEM$GENERATE_SCIM_ACCESS_TOKEN%'

"""

df1 = session.sql(sql_text1).to_pandas()
df2 = session.sql(sql_text2).to_pandas()
df3 = session.sql(sql_text3).to_pandas()
col1, col2,col3 = st.columns(3)

# Add a header to the first column
col1.write('Users by Oldest Password')
col1.write(df1)
# Add a header to the second column
col2.write('Stale Users')
col2.write(df2)
col3.write('SCIM Token Lifecycle')
col3.write(df3)

st.header('Least Privileged Access: Most Dangerous Person')
sql_text ="""
with role_hier as (
    --Extract all Roles
    select
        grantee_name,
        name
    from
        snowflake.account_usage.grants_to_roles
    where
        granted_on = 'ROLE'
        and privilege = 'USAGE'
        and deleted_on is null
    union all
        --Adding in dummy records for "root" roles
    select
        'root',
        r.name
    from
        snowflake.account_usage.roles r
    where
        deleted_on is null
        and not exists (
            select
                1
            from
                snowflake.account_usage.grants_to_roles gtr
            where
                gtr.granted_on = 'ROLE'
                and gtr.privilege = 'USAGE'
                and gtr.name = r.name
                and deleted_on is null
        )
) --CONNECT BY to create the polyarchy and SYS_CONNECT_BY_PATH to flatten it
,
role_path_pre as(
    select
        name,
        level,
        sys_connect_by_path(name, ' -> ') as path
    from
        role_hier connect by grantee_name = prior name start with grantee_name = 'root'
    order by
        path
) --Removing leading delimiter separately since there is some issue with how it interacted with sys_connect_by_path
,
role_path as (
    select
        name,
        level,
        substr(path, len(' -> ')) as path
    from
        role_path_pre
) --Joining in privileges from GRANT_TO_ROLES
,
role_path_privs as (
    select
        path,
        rp.name as role_name,
        privs.privilege,
        granted_on,
        privs.name as priv_name,
        'Role ' || path || ' has ' || privilege || ' on ' || granted_on || ' ' || privs.name as Description
    from
        role_path rp
        left join snowflake.account_usage.grants_to_roles privs on rp.name = privs.grantee_name
        and privs.granted_on != 'ROLE'
        and deleted_on is null
    order by
        path
) --Aggregate total number of priv's per role, including hierarchy
,
role_path_privs_agg as (
    select
        trim(split(path, ' -> ') [0]) role,
        count(*) num_of_privs
    from
        role_path_privs
    group by
        trim(split(path, ' -> ') [0])
    order by
        count(*) desc
) --Most Dangerous Man - final query
select
    grantee_name as user,
    count(a.role) num_of_roles,
    sum(num_of_privs) num_of_privs
from
    snowflake.account_usage.grants_to_users u
    join role_path_privs_agg a on a.role = u.role
where
    u.deleted_on is null
group by
    user
order by
    num_of_privs desc;
"""
df = session.sql(sql_text).to_pandas()

fig = px.bar(df, x="USER", y="NUM_OF_ROLES",color ="USER")
st.plotly_chart(fig, theme="streamlit", use_container_width=True)


st.subheader('Least Privileged Access: Most Bloasted Roles')
sql_text ="""
--Role Hierarchy
with role_hier as (
    --Extract all Roles
    select
        grantee_name,
        name
    from
        snowflake.account_usage.grants_to_roles
    where
        granted_on = 'ROLE'
        and privilege = 'USAGE'
        and deleted_on is null
    union all
        --Adding in dummy records for "root" roles
    select
        'root',
        r.name
    from
        snowflake.account_usage.roles r
    where
        deleted_on is null
        and not exists (
            select
                1
            from
                snowflake.account_usage.grants_to_roles gtr
            where
                gtr.granted_on = 'ROLE'
                and gtr.privilege = 'USAGE'
                and gtr.name = r.name
                and deleted_on is null
        )
) --CONNECT BY to create the polyarchy and SYS_CONNECT_BY_PATH to flatten it
,
role_path_pre as(
    select
        name,
        level,
        sys_connect_by_path(name, ' -> ') as path
    from
        role_hier connect by grantee_name = prior name start with grantee_name = 'root'
    order by
        path
) --Removing leading delimiter separately since there is some issue with how it interacted with sys_connect_by_path
,
role_path as (
    select
        name,
        level,
        substr(path, len(' -> ')) as path
    from
        role_path_pre
) --Joining in privileges from GRANT_TO_ROLES
,
role_path_privs as (
    select
        path,
        rp.name as role_name,
        privs.privilege,
        granted_on,
        privs.name as priv_name,
        'Role ' || path || ' has ' || privilege || ' on ' || granted_on || ' ' || privs.name as Description
    from
        role_path rp
        left join snowflake.account_usage.grants_to_roles privs on rp.name = privs.grantee_name
        and privs.granted_on != 'ROLE'
        and deleted_on is null
    order by
        path
) --Aggregate total number of priv's per role, including hierarchy
,
role_path_privs_agg as (
    select
        trim(split(path, ' -> ') [0]) role,
        count(*) num_of_privs
    from
        role_path_privs
    group by
        trim(split(path, ' -> ') [0])
    order by
        count(*) desc
) 
select * from role_path_privs_agg order by num_of_privs desc
"""

df = session.sql(sql_text).to_pandas()
#st.write(df)
fig = px.bar(df, x="ROLE", y="NUM_OF_PRIVS",color ="ROLE")
st.plotly_chart(fig, theme="streamlit", use_container_width=True)


st.subheader('Configuration Management: Privileged object changes by Users')

sql_text ="""SELECT
    query_text,
    user_name,
    role_name,
    end_time
  FROM snowflake.account_usage.query_history
    WHERE execution_status = 'SUCCESS'
      AND query_type NOT in ('SELECT')
      AND (query_text ILIKE '%create role%'
          OR query_text ILIKE '%manage grants%'
          OR query_text ILIKE '%create integration%'
          OR query_text ILIKE '%create share%'
          OR query_text ILIKE '%create account%'
          OR query_text ILIKE '%monitor usage%'
          OR query_text ILIKE '%ownership%'
          OR query_text ILIKE '%drop table%'
          OR query_text ILIKE '%drop database%'
          OR query_text ILIKE '%create stage%'
          OR query_text ILIKE '%drop stage%'
          OR query_text ILIKE '%alter stage%'
          )
  ORDER BY end_time desc"""

df = session.sql(sql_text).to_pandas()
fig = px.histogram(df, x="USER_NAME",barmode='group')
st.plotly_chart(fig, theme="streamlit", use_container_width=True)

st.subheader('Configuration Management: Network Policy Changes')

sql_text="""select user_name || ' made the following Network Policy change on ' || end_time || ' [' ||  query_text || ']' as Events
   from snowflake.account_usage.query_history where execution_status = 'SUCCESS'
   and query_type in ('CREATE_NETWORK_POLICY', 'ALTER_NETWORK_POLICY', 'DROP_NETWORK_POLICY')
   or (query_text ilike '% set network_policy%' or
       query_text ilike '% unset network_policy%')
       and query_type != 'SELECT' and query_type != 'UNKNOWN'
   order by end_time desc;"""
df = session.sql(sql_text).to_pandas()
st.write(df)