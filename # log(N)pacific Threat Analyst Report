# log(N)pacific Threat Analyst Report - 4/29/2025

## **Summary**
This report investigates the activity of IP address **72.194.40.245**, which was involved in **failed sign-in attempts** across multiple applications in the Azure environment. The user was repeatedly prompted to **enroll in Multi-Factor Authentication (MFA)** due to either a configuration change or a change in the user’s location. The repeated sign-in attempts were identified in the **SigninLogs**, with the user not completing the MFA enrollment process.

## **Reason for Investigation**
The IP address **72.194.40.245** repeatedly attempted to access Azure resources, including the **Microsoft App Access Panel** and **Azure Portal**, but was blocked due to missing MFA enrollment. The activity was flagged as a **potentially suspicious event**, and further investigation was warranted to ensure the security of the environment.

## **Steps Taken**`

1. **Review of Sign-in Logs**:
   - Queried **SigninLogs** in Azure to identify any failed login attempts associated with the IP address `72.194.40.245`.
   - Noted that the **ResultType 50072** (MFA enrollment required) was returned for the user `385733a4939d6a3c890506736ed59a7230f587749022e87f9e66e367550f9da0@lognpacific.com`.

2. **Analysis of Application Access**:
   - Identified that the IP address attempted to access **Microsoft App Access Panel** and **Azure Portal**.
   - Noted that **ResultDescription** consistently pointed to **MFA enrollment issues**.

3. **Verification of User MFA Status**:
   - Suggested verifying the MFA enrollment status for the user in the **Azure AD portal** to ensure that it is correctly set up.
   - Suggested checking **Conditional Access Policies** to ensure no misconfigurations.

4. **Evaluation of IP Behavior**:
   - Observed the behavior pattern, indicating the possibility of **automated login attempts** or a tool attempting to bypass the MFA process.

5. **Recommendation for Further Monitoring**:
   - Suggested setting up **alerts in Azure Sentinel** for future failed login attempts from this IP address to detect potential brute-force attempts or unauthorized access.

6. **Consideration for Blocking the IP**:
   - In the event of suspicious ongoing behavior, recommended blocking the IP address in **NSG** or **Azure Firewall** to prevent further access attempts.

## **Summary of Findings**
- **Repeated MFA Enrollment Prompt**: The user `385733a4939d6a3c890506736ed59a7230f587749022e87f9e66e367550f9da0@lognpacific.com` faced repeated MFA enrollment issues while accessing the **Microsoft App Access Panel** and **Azure Portal**.
- **Not a Brute-Force Attack**: The log results do not show failed password attempts, but rather consistent MFA enrollment prompts.
- **Automated Access Attempt**: It appears there may be an **automated process or script** attempting to access resources, potentially bypassing the MFA process.

## **Next Steps and Recommendations**
1. **Ensure MFA Enrollment**: Confirm the user has successfully enrolled in **multi-factor authentication**.
2. **Review Conditional Access Policies**: Check and modify any **Conditional Access Policies** that may be incorrectly triggering MFA prompts.
3. **Set up Alerts**: Set up **Azure Sentinel alerts** for future login failures or suspicious activity from **72.194.40.245**.
4. **Consider Blocking IP**: If the activity persists and is deemed unauthorized, **block the IP** in your **Azure Firewall** or **NSG**.
5. **User Education**: Inform the user about the need to complete the MFA enrollment process to avoid further interruptions in service.

## **Azure KQL Code Used**

### Query to Identify Failed Sign-ins from Specific IP
The following KQL code was used to identify any failed sign-in attempts from the IP address **72.194.40.245**:

```kql
SigninLogs
| where IPAddress == "72.194.40.245"
| where ResultType != 0  // failed logins
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, ResultDescription
| order by TimeGenerated desc
