package com.teksecur.seleniumzap.selenium_testng_zap.tests;

import org.openqa.selenium.*;
import org.openqa.selenium.chrome.*;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.zaproxy.clientapi.core.*;

import org.apache.commons.io.FileUtils;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.edge.EdgeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.testng.asserts.SoftAssert;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;
import io.github.bonigarcia.wdm.WebDriverManager;

import com.teksecur.seleniumzap.selenium_testng_zap.pages.CartPage;
import com.teksecur.seleniumzap.selenium_testng_zap.pages.HomePage;
import com.teksecur.seleniumzap.selenium_testng_zap.pages.PetStoreMenuPage;
import com.teksecur.seleniumzap.selenium_testng_zap.pages.SignInPage;
import com.teksecur.seleniumzap.selenium_testng_zap.pages.StoreItemPage;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.time.Duration;  
import java.util.Set;
import java.nio.file.Files;
import java.nio.file.Paths;


public class CombinedZapTest {

    private WebDriver driver;
    private ClientApi api;
    private Properties locators;
    private WebDriverWait waiter;
    private static final String ZAP_ADDRESS = "127.0.0.1";
    private static final int ZAP_PORT = 8081;
    private static final String ZAP_API_KEY = "9va1sfnq7oj9mh2scvn7b4doif";  // Set your ZAP API key if required
    private static final String TARGET = "https://petstore.octoperf.com";
    private static final String CONTEXT_NAME = "PetStoreContext";
    private static final String CONTEXT_REGEX = "https://petstore.octoperf.com*";
    //private static final ClientApi zapClient = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);
    private ClientApi zapClient;
    private static final String REPORT_DIR = System.getProperty("REPORT_DIR");
    private static final String REPORT_NAME = System.getProperty("REPORT_NAME");


    @BeforeClass
    public void setUp() throws Exception {
        // Set up ZAP Client
        zapClient = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);

        // Set up Chrome with ZAP Proxy
        String proxyServerUrl = ZAP_ADDRESS + ":" + ZAP_PORT;
        Proxy proxy = new Proxy();
        proxy.setHttpProxy(proxyServerUrl);
        proxy.setSslProxy(proxyServerUrl);

        ChromeOptions co = new ChromeOptions();
        co.setProxy(proxy);
        co.setAcceptInsecureCerts(true);
        co.addArguments("--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage");

        WebDriverManager.chromedriver().setup();
        driver = new ChromeDriver(co);
        driver.manage().timeouts().implicitlyWait(15, TimeUnit.SECONDS);
        waiter = new WebDriverWait(driver, Duration.ofSeconds(10));

        locators = new Properties();
        locators.load(new FileInputStream("config/project.properties"));


        // Clear existing data and create context
        zapClient.core.newSession("PetStoreSession", "true");
        zapClient.context.newContext(CONTEXT_NAME);
        zapClient.context.includeInContext(CONTEXT_NAME, CONTEXT_REGEX);

        // Enable standard ZAP policies
        enableZapPolicies(zapClient);
    }
   
    /*@BeforeClass
    public void setup() throws FileNotFoundException, IOException {
    	try {
            String proxyServerUrl = ZAP_ADDRESS + ":" + ZAP_PORT;
            Proxy proxy = new Proxy();
            proxy.setHttpProxy(proxyServerUrl);
            proxy.setSslProxy(proxyServerUrl);

            ChromeOptions co = new ChromeOptions();
            co.addArguments("--remote-allow-origins=*");
            co.addArguments("--headless");
            co.addArguments("--no-sandbox");
            co.addArguments("--disable-gpu");
            co.addArguments("--disable-dev-shm-usage");
            co.addArguments("--disable-extensions");
            co.setAcceptInsecureCerts(true);
            co.setProxy(proxy);

            WebDriverManager.chromedriver().setup(); // Ensure the version is compatible with your Chrome browser
            driver = new ChromeDriver(co);
            api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);

             // Clear existing data and create context
            zapClient.core.newSession("PetStoreSession", "true");
            zapClient.context.newContext(CONTEXT_NAME);
            zapClient.context.includeInContext(CONTEXT_NAME, CONTEXT_REGEX);

             // Enable standard ZAP policies
            enableZapPolicies(zapClient);


        } catch (Exception e) {
            System.err.println("Error setting up WebDriver: " + e.getMessage());
            e.printStackTrace(); // Print stack trace for detailed debugging
            throw new RuntimeException("Failed to set up WebDriver", e); // Rethrow the exception to fail the setup
        }

    	
        locators = new Properties();
        locators.load(new FileInputStream("config/project.properties"));
        

        

        driver.manage().window().maximize();
        driver.manage().timeouts().pageLoadTimeout(60, TimeUnit.SECONDS);
        driver.manage().timeouts().implicitlyWait(20, TimeUnit.SECONDS);
        waiter = new WebDriverWait(driver, Duration.ofSeconds(10));
    }*/

  



    // ===================== TEST CASES =====================

    // Test 1: Enter Store Test
    @Test(priority = 1)
    public void enterTest() {
        driver.navigate().to("https://petstore.octoperf.com/"); 

        HomePage hp = new HomePage(driver, locators, waiter);
        SoftAssert sa = new SoftAssert();

        hp.clickEnter();
        sa.assertTrue(hp.isEntered());
        sa.assertAll();
    }

    // Test 2: Pet Store Menu Test
    @Test(priority = 2)
    public void verifyUrlTest() {
		PetStoreMenuPage psmp = new PetStoreMenuPage(driver, locators, waiter);
		SoftAssert sa = new SoftAssert();

		sa.assertTrue(psmp.checkLeftNavLinks());
		sa.assertTrue(psmp.checkTopNavLinks());
		sa.assertTrue(psmp.checkImgNavLinks());
	}

	@Test(priority = 3)
	public void linkToRightPageTest() {
		driver.navigate().to(this.locators.getProperty("storeMenuUrl"));

		PetStoreMenuPage psmp = new PetStoreMenuPage(driver, locators, waiter);
		SoftAssert sa = new SoftAssert();
		List<String> species = new ArrayList<>(Arrays.asList("fish", "dogs", "reptiles", "cats", "birds"));

		for (String specie : species) {
			sa.assertTrue(psmp.isLeftNavRight(specie));
		}

		for (String specie : species) {
			sa.assertTrue(psmp.isTopNavRight(specie));
		}

		for (String specie : species) {
			sa.assertTrue(psmp.isImgNavRight(specie));
		}
	}

	@Test(priority = 4)
	public void topMenuContentTest() {
		PetStoreMenuPage psmp = new PetStoreMenuPage(driver, locators, waiter);
		SoftAssert sa = new SoftAssert();

		psmp.clickCartPage();
		sa.assertTrue(psmp.isClickedCartPage());

		psmp.clickSignInPage();
		sa.assertTrue(psmp.isClickedSignInPage());

		psmp.clickHelpPage();
		sa.assertTrue(psmp.isClickedHelpPage());
	}

    

    // Test 4: Sign In Test
    @Test(priority = 5)
    public void signInTest() {
        driver.navigate().to(locators.getProperty("signInUrl"));
        SignInPage sip = new SignInPage(driver, locators, waiter);
        SoftAssert sa = new SoftAssert();
        String username = "jp1";
        String password = "john1";
        sip.signIn(username, password);
        sa.assertTrue(sip.checkSignIn(), "Sign in failed!" + username);
        sa.assertAll();
    }

   //  Test 5: Cart Test 
    @Test(priority = 6 )
    public void addToCartTest() {
        StoreItemPage sip = new StoreItemPage(driver, locators, waiter);
        CartPage cp = new CartPage(driver, locators, waiter);
        SoftAssert sa = new SoftAssert();

        sip.addAllToCart();
        sa.assertTrue(sip.isAdded());
        sa.assertAll();
    }

    @Test(priority = 7)
    public void zapScanAndReportTest() throws Exception {
    // --- Export Selenium cookies into ZAP Session ---
        transferCookiesToZap(driver, zapClient, TARGET);

        // --- Run Spider ---
        System.out.println("Starting Spider Scan...");
        ApiResponse spiderResponse = zapClient.spider.scan(TARGET, null, null, CONTEXT_NAME, null);
        String spiderScanId = ((ApiResponseElement) spiderResponse).getValue();
        monitorScan(zapClient, "spider", spiderScanId);

        // --- Run Active Scan ---
        System.out.println("Starting Active Scan...");
        ApiResponse activeScanResponse = zapClient.ascan.scan(TARGET, "true", "false", null, null, null);
        String activeScanId = ((ApiResponseElement) activeScanResponse).getValue();
        monitorScan(zapClient, "ascan", activeScanId);

        // --- Generate Report ---
        generateHtmlReport();
        System.out.println("✅ Report generated successfully in: " + System.getProperty("user.dir"));
    }
    /*@AfterClass
    public void tearDown() throws Exception {
        
        if (driver != null) {
            driver.quit();
        }

        
       // generateZapReport();
        if ( zapClient!= null) {
            String title = "POC ZAP Selenium - PetStore";
            String template = "traditional-html";
            String description = "PetStore DAST Report Automated by Selenium Test Cases";
            String reportfilename = REPORT_NAME; //"ZAP_REPORT.html";
            String targetFolder = REPORT_DIR;
            try {
                ApiResponse res = zapClient.reports.generate(title, template, null, description, null, null, null,null, null,  reportfilename,null, targetFolder,null);
                System.out.println("Report is generated successfully in the location -> : " + res.toString());
            } catch (ClientApiException ex) {
                throw new Exception(ex);
            }

        }
    }*/

    @AfterClass
    public void tearDown() {
        if (driver != null) driver.quit();
    }

    // -----------------------------------------------------
    // Helper Methods
    // -----------------------------------------------------

    private void monitorScan(ClientApi zap, String type, String scanId) throws ClientApiException, InterruptedException {
        int progress = 0;
        while (progress < 100) {
            Thread.sleep(5000);
            ApiResponse response = type.equals("spider") ? zap.spider.status(scanId) : zap.ascan.status(scanId);
            progress = Integer.parseInt(((ApiResponseElement) response).getValue());
            System.out.println(type + " progress: " + progress + "%");
        }
        System.out.println("✅ " + type + " scan completed!");
    }

    private void transferCookiesToZap(WebDriver driver, ClientApi zap, String domain) throws ClientApiException {
        // For ZAP 1.16.0, HTTP Sessions API requires creating a session first
        Set<Cookie> cookies = driver.manage().getCookies();
        System.out.println("📝 Detected " + cookies.size() + " cookies from Selenium session:");
        
        if (cookies.isEmpty()) {
            System.out.println("⚠️ No cookies found to transfer");
            return;
        }
        
        // Prepare site name (ZAP requires specific format: no protocol, lowercase)
        String site = domain.replace("https://", "").replace("http://", "").toLowerCase();
        String sessionName = "SeleniumSession";
        
        try {
            // Step 1: Create an empty session for the site
            System.out.println("Creating HTTP session: " + sessionName + " for site: " + site);
            zap.httpSessions.createEmptySession(site, sessionName);
            
            // Step 2: Add each cookie as a session token
            for (Cookie cookie : cookies) {
                System.out.println("  - Adding cookie: " + cookie.getName() + " = " + cookie.getValue());
                
                try {
                    // First, add the cookie name as a session token for the site
                    zap.httpSessions.addSessionToken(site, cookie.getName());
                    
                    // Then set the value for that token in our session
                    // Signature: setSessionTokenValue(site, session, sessionToken, tokenValue)
                    zap.httpSessions.setSessionTokenValue(site, sessionName, cookie.getName(), cookie.getValue());
                    
                    System.out.println("    ✓ Successfully added");
                } catch (ClientApiException e) {
                    System.out.println("    ⚠️ Could not add cookie: " + e.getMessage());
                }
            }
            
            // Step 3: Set this session as the active session
            zap.httpSessions.setActiveSession(site, sessionName);
            System.out.println("✅ Activated session: " + sessionName);
            System.out.println("✅ Cookie transfer completed - " + cookies.size() + " cookies added to ZAP session");
            
        } catch (ClientApiException e) {
            System.out.println("⚠️ HTTP Sessions setup failed: " + e.getMessage());
            System.out.println("💡 Workaround: Configure authentication manually in ZAP GUI");
            System.out.println("   OR use Form-Based Authentication instead");
            
            // Print cookie values for manual configuration
            System.out.println("\n📋 Cookie values for manual setup:");
            StringBuilder cookieString = new StringBuilder();
            boolean first = true;
            for (Cookie cookie : cookies) {
                if (!first) cookieString.append("; ");
                cookieString.append(cookie.getName()).append("=").append(cookie.getValue());
                first = false;
            }
            System.out.println("   " + cookieString.toString());
            System.out.println("\n💡 Add this via ZAP GUI: Tools > Options > Replacer");
        }
    }
 

    // Enable all major OWASP policies in ZAP 1.16.0
    private void enableZapPolicies(ClientApi zap) throws ClientApiException {
        // ZAP uses scanner IDs (not policy names) in version 1.16.0
        // Common scanner IDs for OWASP Top 10 vulnerabilities
        
        String[][] scanners = {
            // Scanner ID, Name (for logging)
            {"0", "Directory Browsing"},
            {"6", "Path Traversal"},
            {"7", "Remote File Inclusion"},
            {"40003", "CRLF Injection"},
            {"40008", "Parameter Tampering"},
            {"40009", "Server Side Include"},
            {"40012", "Cross Site Scripting (Reflected)"},
            {"40014", "Cross Site Scripting (Persistent)"},
            {"40016", "Cross Site Scripting (Persistent) - Prime"},
            {"40017", "Cross Site Scripting (Persistent) - Spider"},
            {"40018", "SQL Injection"},
            {"40019", "SQL Injection - MySQL"},
            {"40020", "SQL Injection - Hypersonic SQL"},
            {"40021", "SQL Injection - Oracle"},
            {"40022", "SQL Injection - PostgreSQL"},
            {"40024", "SQL Injection - SQLite"},
            {"90019", "Server Side Code Injection"},
            {"90020", "Remote OS Command Injection"},
            {"90021", "XPath Injection"},
            {"90022", "Application Error Disclosure"},
            {"90023", "XML External Entity Attack"},
            {"90024", "Generic Padding Oracle"},
            {"90025", "Expression Language Injection"},
            {"90026", "SOAP Action Spoofing"},
            {"90028", "Insecure HTTP Method"},
            {"90029", "SOAP XML Injection"},
            {"90030", "WSDL File Detection"}
        };

        System.out.println("🔧 Configuring ZAP Active Scan policies...");
        
        for (String[] scanner : scanners) {
            String scannerId = scanner[0];
            String scannerName = scanner[1];
            
            try {
                // Enable scanner
                zap.ascan.enableScanners(scannerId, null);
                
                // Set attack strength to HIGH
                zap.ascan.setScannerAttackStrength(scannerId, "HIGH", null);
                
                // Set alert threshold to MEDIUM
                zap.ascan.setScannerAlertThreshold(scannerId, "MEDIUM", null);
                
                System.out.println("  ✓ Enabled: " + scannerName + " (ID: " + scannerId + ")");
            } catch (ClientApiException e) {
                System.out.println("  ⚠️ Could not configure scanner " + scannerId + " (" + scannerName + "): " + e.getMessage());
            }
        }
        
        // Set global scan policy settings
        
    }

    // Generate HTML report using ZAP 1.16.0 API
    /*private void generateHtmlReport() throws Exception {
        System.out.println("📄 Generating HTML report...");
        
        try {
            // Get HTML report from ZAP
            ApiResponse reportResponse = zapClient.core.htmlreport();
            String htmlReport = ((ApiResponseElement) reportResponse).getValue();
            
            // Write to file
            String reportPath = System.getProperty("user.dir") + File.separator + "PetStoreZAPReport.html";
            Files.writeString(Paths.get(reportPath), htmlReport);
            
            System.out.println("✅ HTML report saved to: " + reportPath);
            
            // Also generate XML report for CI/CD integration
            ApiResponse xmlReportResponse = zapClient.core.xmlreport();
            String xmlReport = ((ApiResponseElement) xmlReportResponse).getValue();
            String xmlReportPath = System.getProperty("user.dir") + File.separator + "PetStoreZAPReport.xml";
            Files.writeString(Paths.get(xmlReportPath), xmlReport);
            
            System.out.println("✅ XML report saved to: " + xmlReportPath);
            
            // Print summary of findings
            printScanSummary();
            
        } catch (Exception e) {
            System.err.println("❌ Error generating report: " + e.getMessage());
            throw e;
        }
    }*/
   private void generateHtmlReport() throws Exception {
        System.out.println("📄 Generating reports...");
        
        try {
            // Generate HTML report - returns byte[]
            byte[] htmlReportBytes = zapClient.core.htmlreport();
            String reportPath = REPORT_DIR + File.separator + REPORT_NAME;
            Files.write(Paths.get(reportPath), htmlReportBytes);
            System.out.println("✅ HTML report saved to: " + reportPath);
            
            // Generate XML report - returns byte[]
            byte[] xmlReportBytes = zapClient.core.xmlreport();
            String xmlReportPath = REPORT_DIR + File.separator + "PetStoreZAPReport.xml";
            Files.write(Paths.get(xmlReportPath), xmlReportBytes);
            System.out.println("✅ XML report saved to: " + xmlReportPath);
            
            // Print summary of findings
            printScanSummary();
            
        } catch (Exception e) {
            System.err.println("❌ Error generating report: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
   

    // Print a summary of scan findings
    private void printScanSummary() throws ClientApiException {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("SCAN SUMMARY");
        System.out.println("=".repeat(60));
        
        try {
            ApiResponse alertsResponse = zapClient.core.alerts(TARGET, null, null);
            ApiResponseList alertsList = (ApiResponseList) alertsResponse;
            
            int high = 0, medium = 0, low = 0, info = 0;
            
            for (ApiResponse alert : alertsList.getItems()) {
                ApiResponseSet alertSet = (ApiResponseSet) alert;
                String risk = alertSet.getAttribute("risk");
                
                switch (risk) {
                    case "High":
                        high++;
                        break;
                    case "Medium":
                        medium++;
                        break;
                    case "Low":
                        low++;
                        break;
                    case "Informational":
                        info++;
                        break;
                }
            }
            
            System.out.println("Total Alerts: " + alertsList.getItems().size());
            System.out.println("  🔴 High:          " + high);
            System.out.println("  🟠 Medium:        " + medium);
            System.out.println("  🟡 Low:           " + low);
            System.out.println("  🔵 Informational: " + info);
            System.out.println("=".repeat(60) + "\n");
            
            // Print high risk alerts
            if (high > 0) {
                System.out.println("HIGH RISK ALERTS:");
                for (ApiResponse alert : alertsList.getItems()) {
                    ApiResponseSet alertSet = (ApiResponseSet) alert;
                    if ("High".equals(alertSet.getAttribute("risk"))) {
                        System.out.println("  🔴 " + alertSet.getAttribute("alert") + 
                                         " - " + alertSet.getAttribute("url"));
                    }
                }
                System.out.println();
            }
            
        } catch (Exception e) {
            System.out.println("⚠️ Could not retrieve alert summary: " + e.getMessage());
        }
    }


    
    

}
