"""
BugBountyAgent - Browser Controller
====================================
This module controls the browser like a human:
- Opens Chrome/Firefox with visible or headless mode
- Navigates to URLs
- Clicks elements, fills forms, submits data
- Takes screenshots
- Executes JavaScript
- Intercepts network requests
"""

import os
import time
import base64
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from datetime import datetime

from app.core import get_config, log_info, log_warning, log_error, log_debug, get_timestamp

# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright, Browser, Page, BrowserContext, Response
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    log_warning("Playwright not installed. Browser automation will be disabled.")

# Try to import Selenium as fallback
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


class BrowserController:
    """
    Main browser controller for the agent.
    Uses Playwright as primary driver, Selenium as fallback.
    """
    
    def __init__(self, headless: bool = False, proxy: Optional[str] = None):
        """
        Initialize the browser controller.
        
        Args:
            headless: Run browser in headless mode (no GUI)
            proxy: Proxy server URL (e.g., "http://127.0.0.1:8080")
        """
        self.headless = headless or not get_config('agent.permissions.browser_visibility', True)
        self.proxy = proxy
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.is_connected = False
        self.screenshots_dir = get_config('reports.save_dir', './data/reports') + '/screenshots'
        os.makedirs(self.screenshots_dir, exist_ok=True)
        
        log_info(f"BrowserController initialized (headless: {self.headless})")
    
    # ============================================================
    # Connection Methods
    # ============================================================
    
    def connect(self) -> bool:
        """Connect and launch the browser."""
        if self.is_connected:
            log_warning("Browser already connected")
            return True
        
        if not PLAYWRIGHT_AVAILABLE:
            log_error("Playwright not available. Cannot connect browser.")
            return False
        
        try:
            self.playwright = sync_playwright().start()
            
            # Launch browser
            launch_options = {
                'headless': self.headless,
            }
            
            if self.proxy:
                launch_options['proxy'] = {'server': self.proxy}
            
            # Try Chromium first, fallback to Firefox
            try:
                self.browser = self.playwright.chromium.launch(**launch_options)
                log_info("Launched Chromium browser")
            except Exception as e:
                log_warning(f"Chromium launch failed: {e}, trying Firefox")
                self.browser = self.playwright.firefox.launch(**launch_options)
                log_info("Launched Firefox browser")
            
            # Create context with viewport
            self.context = self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent=get_config('targets.user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            )
            
            self.page = self.context.new_page()
            self.is_connected = True
            
            log_info("Browser connected successfully")
            return True
            
        except Exception as e:
            log_error(f"Failed to connect browser: {e}")
            return False
    
    def disconnect(self):
        """Close the browser and cleanup."""
        if self.page:
            try:
                self.page.close()
            except:
                pass
        
        if self.context:
            try:
                self.context.close()
            except:
                pass
        
        if self.browser:
            try:
                self.browser.close()
            except:
                pass
        
        if self.playwright:
            try:
                self.playwright.stop()
            except:
                pass
        
        self.is_connected = False
        log_info("Browser disconnected")
    
    def ensure_connected(self) -> bool:
        """Ensure browser is connected, reconnect if needed."""
        if not self.is_connected:
            return self.connect()
        return True
    
    # ============================================================
    # Navigation Methods
    # ============================================================
    
    def navigate(self, url: str, timeout: int = 30) -> bool:
        """
        Navigate to a URL.
        
        Args:
            url: URL to navigate to
            timeout: Timeout in seconds
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            log_info(f"Navigating to: {url}")
            self.page.goto(url, timeout=timeout * 1000)
            self.page.wait_for_load_state('networkidle')
            log_debug(f"Navigation successful: {url}")
            return True
        except Exception as e:
            log_error(f"Navigation failed: {e}")
            return False
    
    def go_back(self) -> bool:
        """Go back to previous page."""
        if not self.ensure_connected():
            return False
        
        try:
            self.page.go_back()
            return True
        except Exception as e:
            log_error(f"Go back failed: {e}")
            return False
    
    def reload(self) -> bool:
        """Reload the current page."""
        if not self.ensure_connected():
            return False
        
        try:
            self.page.reload()
            return True
        except Exception as e:
            log_error(f"Reload failed: {e}")
            return False
    
    # ============================================================
    # Interaction Methods
    # ============================================================
    
    def click(self, selector: str, timeout: int = 10) -> bool:
        """
        Click an element on the page.
        
        Args:
            selector: CSS selector or XPath
            timeout: Timeout in seconds
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            self.page.wait_for_selector(selector, timeout=timeout * 1000)
            self.page.click(selector)
            log_debug(f"Clicked: {selector}")
            return True
        except Exception as e:
            log_error(f"Click failed on {selector}: {e}")
            return False
    
    def fill(self, selector: str, text: str, timeout: int = 10) -> bool:
        """
        Fill an input field with text.
        
        Args:
            selector: CSS selector or XPath
            text: Text to fill
            timeout: Timeout in seconds
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            self.page.wait_for_selector(selector, timeout=timeout * 1000)
            self.page.fill(selector, text)
            log_debug(f"Filled {selector}: {text[:20]}...")
            return True
        except Exception as e:
            log_error(f"Fill failed on {selector}: {e}")
            return False
    
    def type_text(self, text: str, delay: int = 50) -> bool:
        """
        Type text like a human (with delay between keystrokes).
        
        Args:
            text: Text to type
            delay: Delay between keystrokes in milliseconds
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            self.page.keyboard.type(text, delay=delay)
            log_debug(f"Typed: {text[:20]}...")
            return True
        except Exception as e:
            log_error(f"Type failed: {e}")
            return False
    
    def press_key(self, key: str) -> bool:
        """
        Press a keyboard key.
        
        Args:
            key: Key to press (e.g., "Enter", "Tab", "Escape")
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            self.page.keyboard.press(key)
            log_debug(f"Pressed key: {key}")
            return True
        except Exception as e:
            log_error(f"Key press failed: {e}")
            return False
    
    def select_option(self, selector: str, value: str) -> bool:
        """
        Select an option from a dropdown.
        
        Args:
            selector: CSS selector or XPath
            value: Value to select
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            self.page.select_option(selector, value)
            log_debug(f"Selected option: {value}")
            return True
        except Exception as e:
            log_error(f"Select option failed: {e}")
            return False
    
    def hover(self, selector: str) -> bool:
        """
        Hover over an element.
        
        Args:
            selector: CSS selector or XPath
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            self.page.hover(selector)
            log_debug(f"Hovered: {selector}")
            return True
        except Exception as e:
            log_error(f"Hover failed: {e}")
            return False
    
    def scroll_to(self, selector: Optional[str] = None, x: int = 0, y: int = 0) -> bool:
        """
        Scroll to an element or position.
        
        Args:
            selector: CSS selector or XPath (optional)
            x: X coordinate
            y: Y coordinate
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            if selector:
                self.page.locator(selector).scroll_into_view_if_needed()
            else:
                self.page.evaluate(f"window.scrollTo({x}, {y})")
            log_debug(f"Scrolled to: {selector or f'({x}, {y})'}")
            return True
        except Exception as e:
            log_error(f"Scroll failed: {e}")
            return False
    
    # ============================================================
    # Content Methods
    # ============================================================
    
    def get_text(self, selector: str) -> Optional[str]:
        """
        Get text content of an element.
        
        Args:
            selector: CSS selector or XPath
            
        Returns:
            Optional[str]: Text content or None
        """
        if not self.ensure_connected():
            return None
        
        try:
            return self.page.text_content(selector)
        except Exception as e:
            log_error(f"Get text failed: {e}")
            return None
    
    def get_html(self, selector: Optional[str] = None) -> Optional[str]:
        """
        Get HTML content of the page or an element.
        
        Args:
            selector: CSS selector or XPath (optional)
            
        Returns:
            Optional[str]: HTML content or None
        """
        if not self.ensure_connected():
            return None
        
        try:
            if selector:
                return self.page.inner_html(selector)
            return self.page.content()
        except Exception as e:
            log_error(f"Get HTML failed: {e}")
            return None
    
    def get_url(self) -> Optional[str]:
        """Get current URL."""
        if not self.ensure_connected():
            return None
        
        try:
            return self.page.url
        except Exception as e:
            log_error(f"Get URL failed: {e}")
            return None
    
    def get_title(self) -> Optional[str]:
        """Get page title."""
        if not self.ensure_connected():
            return None
        
        try:
            return self.page.title()
        except Exception as e:
            log_error(f"Get title failed: {e}")
            return None
    
    def evaluate(self, javascript: str) -> Any:
        """
        Execute JavaScript on the page.
        
        Args:
            javascript: JavaScript code to execute
            
        Returns:
            Any: Result of the JavaScript execution
        """
        if not self.ensure_connected():
            return None
        
        try:
            return self.page.evaluate(javascript)
        except Exception as e:
            log_error(f"Evaluate failed: {e}")
            return None
    
    # ============================================================
    # Screenshot Methods
    # ============================================================
    
    def screenshot(self, name: Optional[str] = None) -> Optional[str]:
        """
        Take a screenshot of the current page.
        
        Args:
            name: Screenshot name (optional)
            
        Returns:
            Optional[str]: Path to saved screenshot
        """
        if not self.ensure_connected():
            return None
        
        try:
            timestamp = get_timestamp()
            filename = name or f"screenshot_{timestamp}"
            safe_name = filename.replace(' ', '_').replace('/', '_')
            filepath = f"{self.screenshots_dir}/{safe_name}.png"
            
            self.page.screenshot(path=filepath, full_page=True)
            log_debug(f"Screenshot saved: {filepath}")
            return filepath
        except Exception as e:
            log_error(f"Screenshot failed: {e}")
            return None
    
    def screenshot_base64(self) -> Optional[str]:
        """
        Take a screenshot and return as base64 string.
        
        Returns:
            Optional[str]: Base64 encoded screenshot
        """
        if not self.ensure_connected():
            return None
        
        try:
            screenshot = self.page.screenshot(full_page=True)
            return base64.b64encode(screenshot).decode('utf-8')
        except Exception as e:
            log_error(f"Screenshot base64 failed: {e}")
            return None
    
    # ============================================================
    # Network Methods
    # ============================================================
    
    def get_response(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Get response data for a URL.
        
        Args:
            url: URL to get response for
            
        Returns:
            Optional[Dict]: Response data
        """
        if not self.ensure_connected():
            return None
        
        try:
            # This is a simplified version - in production you'd intercept responses
            response = self.page.request.get(url)
            return {
                'url': response.url,
                'status': response.status,
                'headers': response.headers,
                'body': response.text()
            }
        except Exception as e:
            log_error(f"Get response failed: {e}")
            return None
    
    def intercept_request(self, url_pattern: str, callback):
        """
        Intercept requests matching a URL pattern.
        
        Args:
            url_pattern: URL pattern to intercept
            callback: Function to call on request
        """
        if not self.ensure_connected():
            return
        
        try:
            def route_handler(route, request):
                if url_pattern in request.url:
                    callback(request)
                route.continue_()
            
            self.page.route(url_pattern, route_handler)
            log_debug(f"Request interception setup for: {url_pattern}")
        except Exception as e:
            log_error(f"Request interception failed: {e}")
    
    # ============================================================
    # Human-like Behavior
    # ============================================================
    
    def human_click(self, selector: str, delay: int = 200) -> bool:
        """
        Click like a human (with random delays and movement).
        
        Args:
            selector: CSS selector or XPath
            delay: Delay in milliseconds
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            # Add random delay before clicking
            import random
            time.sleep(random.uniform(0.1, 0.3))
            
            # Get element position
            element = self.page.locator(selector)
            box = element.bounding_box()
            
            if box:
                # Move mouse to element with random offset
                x = box['x'] + box['width'] * random.uniform(0.2, 0.8)
                y = box['y'] + box['height'] * random.uniform(0.2, 0.8)
                self.page.mouse.move(x, y)
                time.sleep(random.uniform(0.05, 0.15))
            
            # Click
            self.page.click(selector)
            log_debug(f"Human click: {selector}")
            return True
            
        except Exception as e:
            log_error(f"Human click failed: {e}")
            return False
    
    def human_type(self, text: str, min_delay: int = 50, max_delay: int = 150) -> bool:
        """
        Type like a human with random delays between keystrokes.
        
        Args:
            text: Text to type
            min_delay: Minimum delay between keystrokes (ms)
            max_delay: Maximum delay between keystrokes (ms)
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            import random
            for char in text:
                self.page.keyboard.type(char)
                time.sleep(random.uniform(min_delay/1000, max_delay/1000))
            
            log_debug(f"Human typed: {text[:20]}...")
            return True
            
        except Exception as e:
            log_error(f"Human type failed: {e}")
            return False
    
    # ============================================================
    # Utility Methods
    # ============================================================
    
    def wait(self, seconds: float):
        """Wait for a specified number of seconds."""
        if not self.ensure_connected():
            return
        
        time.sleep(seconds)
    
    def wait_for_element(self, selector: str, timeout: int = 10) -> bool:
        """
        Wait for an element to appear on the page.
        
        Args:
            selector: CSS selector or XPath
            timeout: Timeout in seconds
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            self.page.wait_for_selector(selector, timeout=timeout * 1000)
            return True
        except Exception as e:
            log_error(f"Wait for element failed: {e}")
            return False
    
    def get_cookies(self) -> List[Dict[str, Any]]:
        """Get all cookies from the current page."""
        if not self.ensure_connected():
            return []
        
        try:
            return self.context.cookies()
        except Exception as e:
            log_error(f"Get cookies failed: {e}")
            return []
    
    def set_cookie(self, name: str, value: str, domain: Optional[str] = None) -> bool:
        """
        Set a cookie.
        
        Args:
            name: Cookie name
            value: Cookie value
            domain: Cookie domain (optional)
            
        Returns:
            bool: Success status
        """
        if not self.ensure_connected():
            return False
        
        try:
            cookie = {'name': name, 'value': value}
            if domain:
                cookie['domain'] = domain
            self.context.add_cookies([cookie])
            log_debug(f"Set cookie: {name}")
            return True
        except Exception as e:
            log_error(f"Set cookie failed: {e}")
            return False
    
    def clear_cookies(self) -> bool:
        """Clear all cookies."""
        if not self.ensure_connected():
            return False
        
        try:
            self.context.clear_cookies()
            log_debug("Cleared all cookies")
            return True
        except Exception as e:
            log_error(f"Clear cookies failed: {e}")
            return False
    
    # ============================================================
    # Context Manager Support
    # ============================================================
    
    def __enter__(self):
        """Enter context manager."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        self.disconnect()