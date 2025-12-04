package com.teksecur.seleniumzap.selenium_testng_zap.pages;

import java.util.List;
import java.util.Properties;

import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.support.ui.ExpectedConditions;


public class CartPage {
	private WebDriver driver;
	private Properties locators;
	private WebDriverWait waiter;

	public CartPage(WebDriver driver, Properties locators, WebDriverWait waiter) {
		this.driver = driver;
		this.locators = locators;
		this.waiter = waiter;
	}
	
	public void deleteAllCookies() {
		driver.navigate().to(locators.getProperty("cartPageUrl"));
		driver.manage().deleteAllCookies();
		driver.navigate().refresh();
	}

	public WebElement getEmptyCartMsg() {
		return this.driver.findElement(By.xpath(this.locators.getProperty("emptyCartMsg")));
	}

	public boolean isEmpty() {
		return this.getEmptyCartMsg().getText().contains("Your cart is empty.");
	}
	
	public List<WebElement> getTotalCost() {
		return this.driver.findElements(By.xpath(this.locators.getProperty("totalCost")));
	}
	
	public WebElement getSubTotal() {
		return this.driver.findElement(By.xpath(this.locators.getProperty("subTotal")));
	}
	
	private int sumTotalCost() {
		List<WebElement> list = this.getTotalCost();
		double sum = 0;
		for (int i = 0; i < list.size(); i++) {
			String price = list.get(i).getText().substring(1);
			double total = Double.parseDouble(price);
			sum += total; 
		}	
		int sumT = (int) (sum * 100);
		return sumT;	
	}
	
	private int subTotal() {		
		String subTotal = this.getSubTotal().getText().substring(12);
		double total = Double.parseDouble(subTotal);
		int subT = (int) (total * 100);
		return subT;
	}
	
	public boolean isEqual() {
		boolean equal = false;
		if (this.sumTotalCost() == this.subTotal()) {
			equal = true;
		}
		return equal;
		
	}
}
