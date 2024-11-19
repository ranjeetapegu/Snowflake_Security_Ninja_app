# Snowflake_Security_Ninja_app

what is this?
It is a streamlit app inside snowflake to help to monitor the security events in the account. This app is based on the project [Snow Sentry](https://quickstarts.snowflake.com/guide/security_dashboards_for_snowflake/index.html#0) which was developed to help the customer to know how secure is their snowflake account.

How does it helps? 

My customer always has one ask:  
'How safe is my Snowflake account and to get a deeper understanding of their Snowflake account?' 
 This app will facilitate this conversation and help in taking corrective measures.

The app covers:-
1. Authentication patterns: Failed login attempts organized by user and reason, and account-wide visibility of the authentication types in use.
2. Roles: RBAC maturity ratings, AccountAdmin usage monitoring, least-used roles for users.
3. Users: Most dangerous user, disabled users not yet dropped, and users with stale passwords.
4. Configuration drift: Deviations from baseline normal to network policies, security integrations, replication, and failback-enabled Snowflake Accounts.
