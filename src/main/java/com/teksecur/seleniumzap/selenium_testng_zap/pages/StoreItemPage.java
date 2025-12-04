package com.teksecur.seleniumzap.selenium_testng_zap.pages;

import java.util.List;
import java.util.Properties;

import org.openqa.selenium.By;
import org.openqa.selenium.By.ByLinkText;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.WebDriverWait;

import com.teksecur.seleniumzap.selenium_testng_zap.utils.ExcelUtils;

//import com.teksecur.seleniumzap.selenium_testng_zap.utils.ExcelUtils;

public class StoreItemPage {
	private WebDriver driver;
	private Properties locators;
	private WebDriverWait waiter;

	public StoreItemPage(WebDriver driver, Properties locators, WebDriverWait waiter) {
		this.driver = driver;
		this.locators = locators;
		this.waiter = waiter;
	}
	
	public WebElement getAddToCartBtn() {
		return this.driver.findElement(By.xpath(this.locators.getProperty("addToCartBtn")));
	}

	public void clickAddToCartBtn() {
		this.getAddToCartBtn().click();
	}
	
	// Adding to cart method using Excel data
	public void addAllToCart() {
		ExcelUtils.setExcell(this.locators.getProperty("dataSource"));
		ExcelUtils.setWorkSheet(0);
		
		for (int i = 1; i < ExcelUtils.getRowNumber(); i++) {
			this.driver.navigate().to(ExcelUtils.getDataAt(i, 1));
			this.clickAddToCartBtn();
		}
	}
	
	public List<WebElement> getCartId() {
		return this.driver.findElements(By.xpath(this.locators.getProperty("idCartList")));
	}
	
	// Check method using Excel data
	public boolean isAdded() {
		boolean added = false;
		ExcelUtils.setExcell(this.locators.getProperty("dataSource"));
		ExcelUtils.setWorkSheet(0);

		for (int i = 1; i < ExcelUtils.getRowNumber(); i++) {
			if (getCartId().toString().equals(ExcelUtils.getDataAt(i, 0))) {
				break;
			}
			added = true;
		}
		return added;
	}
}
