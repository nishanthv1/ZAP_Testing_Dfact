package com.teksecur.seleniumzap.selenium_testng_zap.pages;

import java.util.Properties;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.WebDriverWait;

public class HomePage {
	private WebDriver driver;
	private Properties locators;
	private WebDriverWait waiter;

	public HomePage(WebDriver driver, Properties locators, WebDriverWait waiter) {
		this.driver = driver;
		this.locators = locators;
		this.waiter = waiter;
	}
	
	public WebElement getEnter() {
		return this.driver.findElement(By.xpath(this.locators.getProperty("enterTheStore")));
	}

	public void clickEnter() {
		this.getEnter().click();
	}

	public WebElement getSignInBtn() {
		return this.driver.findElement(By.xpath(this.locators.getProperty("signInPageLink")));
	}

	public boolean isEntered() {
		return this.getSignInBtn().getText().contains("Sign In");
	}
}
