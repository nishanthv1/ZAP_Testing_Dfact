package com.teksecur.seleniumzap.selenium_testng_zap.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

public class ExcelUtils {
	private static XSSFWorkbook wb = null;
	private static XSSFSheet sheet = null;
	private static String excellPath;

	public static boolean setExcell(String path) {
		if (wb != null) {
			try {
				wb.close();
			} catch (Exception e) {
				System.out.println(e.toString());
				return false;
			}
		}
		File f = new File(path);
		try {
			FileInputStream fis = new FileInputStream(f);

			wb = new XSSFWorkbook(fis);
			excellPath = path;
			return true;
		} catch (Exception e) {
			System.out.println(e.toString());
			System.out.println("Bad file opening!");
			return false;
		}
	}

	public static boolean setWorkSheet(int index) {
		try {
			sheet = wb.getSheetAt(index);
			return true;
		} catch (Exception e) {
			System.out.println(e.toString());
			System.out.println("Bad opening of worksheet!");
			return false;
		}
	}

	public static String getDataAt(int row, int column) {
		try {
			XSSFRow r = sheet.getRow(row);
			XSSFCell celija = r.getCell(column);
			return celija.toString();
		} catch (NullPointerException e) {
			System.out.println(e.toString());
			System.out.println("Something is null!");
		} catch (Exception e) {
			System.out.println(e.toString());
			System.out.println("An Error occurred!");
		}
		return "";
	}

	public static String getDataAtNum(int row, int column) {
		try {
			XSSFRow r = sheet.getRow(row);
			XSSFCell celija = r.getCell(column);
			double br = celija.getNumericCellValue();
			String rez = "";
			rez = rez + (int) br;
			return rez;
		} catch (NullPointerException e) {
			System.out.println(e.toString());
			System.out.println("Something is null!");
		} catch (Exception e) {
			System.out.println(e.toString());
			System.out.println("AN Error occurred!");
		}
		return "";
	}

	public static boolean setDataAt(int row, int column, String data) {
		try {
			XSSFRow r = sheet.getRow(row);
			if (r == null) {
				r = sheet.createRow(row);
			}
			XSSFCell celija = r.getCell(column);
			if (celija == null) {
				celija = r.createCell(column);
			}
			celija.setCellValue(data);
			FileOutputStream fos = new FileOutputStream(excellPath);
			wb.write(fos);
			return true;
		} catch (Exception e) {
			System.out.println(e.toString());
			System.out.println("An Error occurred!");
			return false;
		}
	}

	public static boolean setRandomAt(int row, int column) {
		String idOne = UUID.randomUUID().toString();
		String data = idOne.substring(0, 5);
		try {
			XSSFRow r = sheet.getRow(row);
			if (r == null) {
				r = sheet.createRow(row);
			}
			XSSFCell celija = r.getCell(column);
			if (celija == null) {
				celija = r.createCell(column);
			}
			celija.setCellValue(data);
			FileOutputStream fos = new FileOutputStream(excellPath);
			wb.write(fos);
			return true;
		} catch (Exception e) {
			System.out.println(e.toString());
			System.out.println("An Error occurred!");
			return false;
		}
	}
	
	public static boolean setLangRandomAt(int row, int column) {
		List<String> myList = Arrays.asList("english", "japanese");
		Random rand = new Random();
	    int randomitem = rand.nextInt(myList.size());
	    String data = myList.get(randomitem);
		try {
			XSSFRow r = sheet.getRow(row);
			if (r == null) {
				r = sheet.createRow(row);
			}
			XSSFCell celija = r.getCell(column);
			if (celija == null) {
				celija = r.createCell(column);
			}
			celija.setCellValue(data);
			FileOutputStream fos = new FileOutputStream(excellPath);
			wb.write(fos);
			return true;
		} catch (Exception e) {
			System.out.println(e.toString());
			System.out.println("An Error occurred!");
			return false;
		}
	}
	
	public static boolean setFavCategRandomAt(int row, int column) {
		List<String> myList = Arrays.asList("FISH", "DOGS", "REPTILES", "CATS", "BIRDS");
		Random rand = new Random();
	    int randomitem = rand.nextInt(myList.size());
	    String data = myList.get(randomitem);
		try {
			XSSFRow r = sheet.getRow(row);
			if (r == null) {
				r = sheet.createRow(row);
			}
			XSSFCell celija = r.getCell(column);
			if (celija == null) {
				celija = r.createCell(column);
			}
			celija.setCellValue(data);
			FileOutputStream fos = new FileOutputStream(excellPath);
			wb.write(fos);
			return true;
		} catch (Exception e) {
			System.out.println(e.toString());
			System.out.println("An Error occurred!");
			return false;
		}
	}

	public static int getRowNumber() {
		try {

			return sheet.getLastRowNum() + 1;
		} catch (Exception e) {
			System.out.println(e.toString());
			System.out.println("An Error occurred!");
			return -1;
		}
	}

	public static boolean closeExcell() {
		if (wb != null) {
			try {
				wb.close();
				wb = null;
				return true;
			} catch (IOException e) {
				e.printStackTrace();
				wb = null;
				return false;
			}
		}
		return true;
	}

}
