"""
BugBountyAgent - Browser Controller
=====================================
Controls your browser like a human using Playwright.
Opens, navigates, clicks, types, and intercepts traffic.
"""

import os
import time
import base64
from typing import Optional, Dict, Any, List
from datetime import datetime

from .config import Config
from .logging import log_info, log_error, log_warning, log_debug


class BrowserController:
    """
    Browser automation controller.
    Acts like a human using Playwright.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.is_connected = False
        self.headless = config.get('browser.headless', False)
        self.proxy = config.get('browser.proxy', None)
        
        # Try to import Playwright
        try:
            from playwright.sync_api import sync_playwright
            self.playwright_module = sync_playwright
            self.playwright_available = True
        except ImportError:
            self.playwright_available = False
            log_warning("Playwright not installed. Browser automation disabled.")
    
    def connect(self) -> bool:
        """Launch and connect to browser."""
        if not self.playwright_available:
            log_error("Playwright not available")
            return False
        
        if self.is_connected:
            return True
        
        try:
            self.playwright = self.playwright_module().start()
            
            launch_options = {'headless': self.headless}
            if self.proxy:
                launch_options['proxy'] = {'server': self.proxy}
            
            # Try Chromium first
            try:
                self.browser = self.playwright.chromium.launch(**launch_options)
                log_info("✅ Chromium launched")
            except Exception as e:
                log_warning(f"Chromium failed: {e}, trying Firefox")
                self.browser = self.playwright.firefox.launch(**launch_options)
                log_info("✅ Firefox launched")
            
            self.context = self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            self.page = self.context.new_page()
            self.is_connected = True
            log_info("✅ Browser connected")
            return True
            
        except Exception as e:
            log_error(f"Browser connection failed: {e}")
            return False
    
    def disconnect(self):
        """Close browser."""
        try:
            if self.page:
                self.page.close()
            if self.context:
                self.context.close()
            if self.browser:
                self.browser.close()
            if self.playwright:
                self.playwright.stop()
            self.is_connected = False
            log_info("Browser disconnected")
        except:
            pass
    
    def ensure_connected(self) -> bool:
        """Ensure browser is connected."""
        if not self.is_connected:
            return self.connect()
        return True
    
    # ============================================================
    # Navigation
    # ============================================================
    
    def navigate(self, url: str, timeout: int = 30) -> bool:
        """Navigate to a URL."""
        if not self.ensure_connected():
            return False
        
        try:
            log_info(f"🌐 Navigating to: {url}")
            self.page.goto(url, timeout=timeout * 1000)
            self.page.wait_for_load_state('networkidle')
            return True
        except Exception as e:
            log_error(f"Navigation failed: {e}")
            return False
    
    def go_back(self) -> bool:
        """Go back one page."""
        if not self.ensure_connected():
            return False
        try:
            self.page.go_back()
            return True
        except Exception as e:
            log_error(f"Go back failed: {e}")
            return False
    
    # ============================================================
    # Interactions
    # ============================================================
    
    def click(self, selector: str, timeout: int = 10) -> bool:
        """Click an element."""
        if not self.ensure_connected():
            return False
        
        try:
            self.page.wait_for_selector(selector, timeout=timeout * 1000)
            self.page.click(selector)
            log_debug(f"🖱️ Clicked: {selector}")
            return True
        except Exception as e:
            log_error(f"Click failed: {e}")
            return False
    
    def fill(self, selector: str, text: str, timeout: int = 10) -> bool:
        """Fill an input field."""
        if not self.ensure_connected():
            return False
        
        try:
            self.page.wait_for_selector(selector, timeout=timeout * 1000)
            self.page.fill(selector, text)
            log_debug(f"⌨️ Filled: {selector} = {text[:20]}...")
            return True
        except Exception as e:
            log_error(f"Fill failed: {e}")
            return False
    
    def type_text(self, text: str, delay: int = 50) -> bool:
        """Type like a human with delays."""
        if not self.ensure_connected():
            return False
        
        try:
            self.page.keyboard.type(text, delay=delay)
            return True
        except Exception as e:
            log_error(f"Type failed: {e}")
            return False
    
    def press_key(self, key: str) -> bool:
        """Press a keyboard key."""
        if not self.ensure_connected():
            return False
        
        try:
            self.page.keyboard.press(key)
            return True
        except Exception as e:
            log_error(f"Key press failed: {e}")
            return False
    
    def hover(self, selector: str) -> bool:
        """Hover over an element."""
        if not self.ensure_connected():
            return False
        
        try:
            self.page.hover(selector)
            return True
        except Exception as e:
            log_error(f"Hover failed: {e}")
            return False
    
    def scroll_to(self, selector: Optional[str] = None, x: int = 0, y: int = 0) -> bool:
        """Scroll to an element or position."""
        if not self.ensure_connected():
            return False
        
        try:
            if selector:
                self.page.locator(selector).scroll_into_view_if_needed()
            else:
                self.page.evaluate(f"window.scrollTo({x}, {y})")
            return True
        except Exception as e:
            log_error(f"Scroll failed: {e}")
            return False
    
    # ============================================================
    # Content Extraction
    # ============================================================
    
    def get_text(self, selector: str) -> Optional[str]:
        """Get text content of an element."""
        if not self.ensure_connected():
            return None
        
        try:
            return self.page.text_content(selector)
        except Exception as e:
            log_error(f"Get text failed: {e}")
            return None
    
    def get_html(self, selector: Optional[str] = None) -> Optional[str]:
        """Get HTML content."""
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
        except:
            return None
    
    def get_title(self) -> Optional[str]:
        """Get page title."""
        if not self.ensure_connected():
            return None
        try:
            return self.page.title()
        except:
            return None
    
    def evaluate(self, javascript: str) -> Any:
        """Execute JavaScript."""
        if not self.ensure_connected():
            return None
        
        try:
            return self.page.evaluate(javascript)
        except Exception as e:
            log_error(f"Evaluate failed: {e}")
            return None
    
    # ============================================================
    # Screenshots
    # ============================================================
    
    def screenshot(self, name: Optional[str] = None) -> Optional[str]:
        """Take a screenshot."""
        if not self.ensure_connected():
            return None
        
        try:
            os.makedirs('data/screenshots', exist_ok=True)
            filename = name or f"screenshot_{int(time.time())}"
            filepath = f"data/screenshots/{filename}.png"
            self.page.screenshot(path=filepath, full_page=True)
            log_debug(f"📸 Screenshot: {filepath}")
            return filepath
        except Exception as e:
            log_error(f"Screenshot failed: {e}")
            return None
    
    def screenshot_base64(self) -> Optional[str]:
        """Take screenshot as base64."""
        if not self.ensure_connected():
            return None
        
        try:
            screenshot = self.page.screenshot(full_page=True)
            return base64.b64encode(screenshot).decode('utf-8')
        except Exception as e:
            log_error(f"Screenshot base64 failed: {e}")
            return None
    
    # ============================================================
    # Network Interception
    # ============================================================
    
    def intercept_requests(self, url_pattern: str, callback):
        """Intercept network requests."""
        if not self.ensure_connected():
            return
        
        try:
            def route_handler(route, request):
                if url_pattern in request.url:
                    callback(request)
                route.continue_()
            
            self.page.route(url_pattern, route_handler)
            log_debug(f"🔍 Intercepting: {url_pattern}")
        except Exception as e:
            log_error(f"Intercept failed: {e}")
    
    # ============================================================
    # Human-like Behavior
    # ============================================================
    
    def human_click(self, selector: str, delay: int = 200) -> bool:
        """Click with random delays."""
        if not self.ensure_connected():
            return False
        
        try:
            import random
            time.sleep(random.uniform(0.1, 0.3))
            
            # Get element position and move mouse
            element = self.page.locator(selector)
            box = element.bounding_box()
            if box:
                x = box['x'] + box['width'] * random.uniform(0.2, 0.8)
                y = box['y'] + box['height'] * random.uniform(0.2, 0.8)
                self.page.mouse.move(x, y)
                time.sleep(random.uniform(0.05, 0.15))
            
            self.page.click(selector)
            return True
        except Exception as e:
            log_error(f"Human click failed: {e}")
            return False
    
    def human_type(self, text: str, min_delay: int = 50, max_delay: int = 150) -> bool:
        """Type with random delays."""
        if not self.ensure_connected():
            return False
        
        try:
            import random
            for char in text:
                self.page.keyboard.type(char)
                time.sleep(random.uniform(min_delay/1000, max_delay/1000))
            return True
        except Exception as e:
            log_error(f"Human type failed: {e}")
            return False