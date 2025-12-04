package com.teksecur.seleniumzap.selenium_testng_zap;


import java.io.FileInputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

//import org.junit.jupiter.api.Test;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.testng.asserts.SoftAssert;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import com.teksecur.seleniumzap.selenium_testng_zap.pages.CartPage;
import com.teksecur.seleniumzap.selenium_testng_zap.pages.HomePage;
import com.teksecur.seleniumzap.selenium_testng_zap.pages.PetStoreMenuPage;
import com.teksecur.seleniumzap.selenium_testng_zap.pages.SignInPage;
import com.teksecur.seleniumzap.selenium_testng_zap.pages.StoreItemPage;

/**
 * Unit test for simple App.
 */
public class AppTest {
	/**
	 * Test
	 */
}