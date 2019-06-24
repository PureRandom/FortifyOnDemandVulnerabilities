# Fortify On Demand Vulnerbility Reporting

This is an Azure DevOps task that gets the lastest count of the vulnerbilities in your Fortify On Demand release to then vallidate it is below the configured level.

You can configure each level of Critical, High, Medium and Low to make sure it aligns to your limits in the DevOps pipeline. This can prevent new unsecure code ever making it further into the Software Delivery Life Cycle.

## Usage
The task uses the Fortify On Demand API and perticularly the 'Vulnerbilities' API.
You can put this task either in your Build Definition or Release Piepline, to prevent code with vulnerbilites above your configured amount further.

Please configure the task variables as below:

**Fortify Details**

Release ID = The Release ID of the scans to validate against.<br/>
API URL = The Data Centers URL for the API Layer - (API URL Options)[https://emea.fortify.com/Docs/en/index.htm#Additional_Services/API/API_About.htm%3FTocPath%3DAPI%7C_____0]

**Vulnerbilities Limites**

Max Critical Issues = Maximum Critical Issues <br/>
Max High Issues = Maximum High Issues <br/>
Max Medium Issues = Maximum Medium Issues<br/>
Max Low Issues = Maximum Low Issues

**API Details**
API Key = Fortify API Key <br/>
API Secret = Fortify API Secret Key

**Reporting**
Alert Level = 'error' to escape on breach or 'warning' to only alert on breach <br/>
Reporting Level = 'results' to print out only the results of the scan or 'verbose' to print out the full response.

## Further Information
- Fortify On Demand API Swagger - [Vulnerbilites API](https://api.emea.fortify.com/swagger/ui/index#!/Vulnerabilities/VulnerabilitiesV3_GetVulnerabilities)
- Fortify API Documentation - [API Documentation](https://emea.fortify.com/Docs/en/index.htm#Additional_Services/API/API_About.htm%3FTocPath%3DAPI%7C_____0)
- Christopher Pateman - [PR Code](https://prcode.blog)

## Support
All bugs found, please raise a bug on the Git Hub Issues.

## Legal
This is not an offical task by Fortify or sponsored by Fortify. The extension is produced independently of Fortify.
