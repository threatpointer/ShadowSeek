# System Architecture Patterns - ShadowSeek

## 🔧 **Configuration Management Patterns**

### **Environment Variable-Based Configuration** ⭐ **NEW PATTERN**
**Problem**: Hardcoded system paths prevent deployment across different systems
**Solution**: Complete environment variable-driven configuration system

```python
# Pattern: Environment Variable with Fallback
def get_config_value(env_var, default=None, required=False):
    """Get configuration value from environment with proper error handling"""
    value = os.environ.get(env_var, default)
    if required and not value:
        logger.error(f"{env_var} is required but not set")
        raise ConfigurationError(f"Missing required configuration: {env_var}")
    return value

# Usage in flask_app/config.py
class Config:
    GHIDRA_INSTALL_DIR = os.environ.get('GHIDRA_INSTALL_DIR')
    GHIDRA_BRIDGE_PORT = int(os.environ.get('GHIDRA_BRIDGE_PORT', '4768'))
    GHIDRA_PROJECTS_DIR = os.environ.get('GHIDRA_PROJECTS_DIR') or os.path.join(os.getcwd(), 'ghidra_projects')
```

### **Automated Path Detection Pattern** ⭐ **NEW PATTERN**
**Pattern**: Auto-detect installations while allowing environment override

```python
def _find_ghidra_path(self):
    """Find Ghidra installation path from environment variables only"""
    # Priority 1: Environment variable
    ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
    if ghidra_path and os.path.exists(ghidra_path):
        return ghidra_path
    
    # Priority 2: .env file
    env_path = Path('.env')
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                if line.startswith('GHIDRA_INSTALL_DIR='):
                    path = line.split('=', 1)[1].strip().strip('"\'')
                    if path and os.path.exists(path):
                        return path
    
    # No hardcoded fallbacks - user must configure
    logger.error("GHIDRA_INSTALL_DIR not found in environment variables or .env file")
    return None
```

### **Configuration Validation Pattern** ⭐ **NEW PATTERN**
**Pattern**: Comprehensive validation with clear error messages

```python
def validate_configuration(config):
    """Validate configuration with detailed feedback"""
    valid = True
    
    # Required path validation
    ghidra_path = config.get("GHIDRA_INSTALL_DIR")
    if not ghidra_path:
        print_status("GHIDRA_INSTALL_DIR is required", "error")
        valid = False
    elif not os.path.exists(ghidra_path):
        print_status(f"Ghidra path does not exist: {ghidra_path}", "error")
        valid = False
    else:
        # Component validation
        support_dir = os.path.join(ghidra_path, "support")
        if os.path.exists(support_dir):
            print_status("Ghidra installation validated", "success")
        else:
            print_status(f"Invalid Ghidra installation: missing support directory", "error")
            valid = False
    
    return valid
```

## 🚀 **Automated Setup Patterns**

### **Interactive Setup Pattern** ⭐ **NEW PATTERN**
**Pattern**: Guided configuration with auto-detection and smart defaults

```python
def prompt_for_paths(found_paths):
    """Interactive configuration with auto-detection"""
    config = {}
    
    # Auto-detection with user override
    default_ghidra = found_paths.get("GHIDRA_INSTALL_DIR", "")
    if default_ghidra:
        print_status(f"Found Ghidra installation: {default_ghidra}", "success")
        ghidra_path = input(f"Ghidra installation path [{default_ghidra}]: ").strip()
    else:
        print_status("No Ghidra installation found automatically", "warning")
        ghidra_path = input("Ghidra installation path (REQUIRED): ").strip()
    
    config["GHIDRA_INSTALL_DIR"] = ghidra_path if ghidra_path else default_ghidra
    
    return config
```

### **Automated Component Startup Pattern** ⭐ **NEW PATTERN**
**Pattern**: Automatic service startup with status monitoring

```python
def run_start_all():
    """Start all ShadowSeek components automatically"""
    if not os.path.exists("start_all.bat"):
        print_status("start_all.bat not found", "error")
        return False
    
    try:
        print_status("Starting ShadowSeek components...", "info")
        
        if platform.system() == "Windows":
            subprocess.Popen(["start_all.bat"], shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE)
        
        print_status("Components starting up...", "info", "Waiting 3 seconds")
        time.sleep(3)
        
        print_status("ShadowSeek components started successfully", "success")
        return True
        
    except Exception as e:
        print_status(f"Error starting components: {e}", "error")
        return False
```

### **Comprehensive Testing Pattern** ⭐ **NEW PATTERN**
**Pattern**: Multi-layer validation with real component testing

```python
def test_system_ready():
    """Test all system components and configuration"""
    results = {
        'Environment Variables': test_environment_variables(),
        'Ghidra Installation': test_ghidra_installation(),
        'Python Environment': test_python_environment(),
        'Directory Structure': test_directory_structure(),
        'Flask Configuration': test_flask_config(),
        'Network Configuration': test_network_configuration(),
        'Component Connectivity': test_running_components()
    }
    
    success = all(results.values())
    return success, results
```

## 🏗️ **Application Architecture Patterns**

### **Flask Application Factory Pattern** (Enhanced)
**Pattern**: Environment-aware application factory

```python
def create_app(test_config=None):
    """Create Flask app with environment-based configuration"""
    app = Flask(__name__, instance_relative_config=True)
    
    # Load environment-based configuration
    app.config.from_object('flask_app.config.Config')
    
    # Initialize components with environment validation
    db.init_app(app)
    
    # Initialize bridge manager with environment detection
    from flask_app.ghidra_bridge_manager import GhidraBridgeManager
    ghidra_bridge_manager = GhidraBridgeManager(app)
    app.ghidra_bridge_manager = ghidra_bridge_manager
    
    return app
```

### **Service Discovery Pattern** (Enhanced)
**Pattern**: Environment-based service configuration

```python
class ServiceConfig:
    """Environment-based service configuration"""
    
    @staticmethod
    def get_ghidra_config():
        return {
            'install_dir': os.environ.get('GHIDRA_INSTALL_DIR'),
            'bridge_port': int(os.environ.get('GHIDRA_BRIDGE_PORT', '4768')),
            'projects_dir': os.environ.get('GHIDRA_PROJECTS_DIR', './ghidra_projects'),
            'temp_dir': os.environ.get('GHIDRA_TEMP_DIR', './temp/ghidra_temp')
        }
    
    @staticmethod
    def validate_service_config():
        """Validate all service configurations"""
        config = ServiceConfig.get_ghidra_config()
        if not config['install_dir']:
            raise ConfigurationError("GHIDRA_INSTALL_DIR not configured")
        if not os.path.exists(config['install_dir']):
            raise ConfigurationError(f"Ghidra installation not found: {config['install_dir']}")
```

## 📁 **File System Patterns**

### **Configurable Directory Pattern** ⭐ **NEW PATTERN**
**Pattern**: All directories configurable via environment variables

```python
class DirectoryManager:
    """Manage all application directories via environment variables"""
    
    @staticmethod
    def get_directories():
        return {
            'upload': os.environ.get('UPLOAD_FOLDER', './uploads'),
            'temp': os.environ.get('TEMP_FOLDER', './temp'),
            'logs': os.environ.get('LOG_FOLDER', './logs'),
            'ghidra_projects': os.environ.get('GHIDRA_PROJECTS_DIR', './ghidra_projects'),
            'ghidra_temp': os.environ.get('GHIDRA_TEMP_DIR', './temp/ghidra_temp')
        }
    
    @staticmethod
    def ensure_directories():
        """Create all required directories"""
        directories = DirectoryManager.get_directories()
        for name, path in directories.items():
            os.makedirs(path, exist_ok=True)
            logger.info(f"Directory ready: {name} -> {path}")
```

### **Portable Path Pattern** ⭐ **NEW PATTERN**
**Pattern**: Cross-platform path handling with environment configuration

```python
def get_platform_specific_path(base_path, filename):
    """Get platform-specific executable path"""
    if platform.system() == "Windows":
        return os.path.join(base_path, f"{filename}.bat")
    else:
        return os.path.join(base_path, filename)

# Usage for Ghidra headless analyzer
def get_headless_analyzer_path():
    ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
    if not ghidra_path:
        raise ConfigurationError("GHIDRA_INSTALL_DIR not configured")
    
    support_dir = os.path.join(ghidra_path, "support")
    return get_platform_specific_path(support_dir, "analyzeHeadless")
```

## 🔍 **Testing and Validation Patterns**

### **Multi-Layer Validation Pattern** ⭐ **NEW PATTERN**
**Pattern**: Validate configuration, installation, and runtime components

```python
class SystemValidator:
    """Multi-layer system validation"""
    
    @staticmethod
    def validate_environment():
        """Validate environment variables"""
        required_vars = ['GHIDRA_INSTALL_DIR', 'GHIDRA_BRIDGE_PORT', 'FLASK_PORT']
        for var in required_vars:
            if not os.environ.get(var):
                raise ValidationError(f"Required environment variable not set: {var}")
    
    @staticmethod
    def validate_installation():
        """Validate Ghidra installation"""
        ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
        if not os.path.exists(ghidra_path):
            raise ValidationError(f"Ghidra installation not found: {ghidra_path}")
        
        headless = get_headless_analyzer_path()
        if not os.path.exists(headless):
            raise ValidationError(f"Headless analyzer not found: {headless}")
    
    @staticmethod
    def validate_runtime():
        """Validate running components"""
        flask_port = int(os.environ.get('FLASK_PORT', '5000'))
        bridge_port = int(os.environ.get('GHIDRA_BRIDGE_PORT', '4768'))
        
        # Test component connectivity
        for port, name in [(flask_port, 'Flask'), (bridge_port, 'Bridge')]:
            if not test_port_connectivity('localhost', port):
                raise ValidationError(f"{name} not running on port {port}")
```

### **Auto-Recovery Pattern** ⭐ **NEW PATTERN**
**Pattern**: Automatic directory creation and component restart

```python
def ensure_system_ready():
    """Ensure system is ready with auto-recovery"""
    try:
        # Ensure directories exist
        DirectoryManager.ensure_directories()
        
        # Validate configuration
        SystemValidator.validate_environment()
        SystemValidator.validate_installation()
        
        # Test runtime (non-critical)
        try:
            SystemValidator.validate_runtime()
        except ValidationError as e:
            logger.warning(f"Runtime validation failed: {e}")
            logger.info("Components may need to be started manually")
        
        return True
        
    except ValidationError as e:
        logger.error(f"System validation failed: {e}")
        return False
```

## 🎯 **Key Pattern Benefits**

### **Portability Patterns**:
- ✅ **Zero Hardcoded Paths**: All paths configurable via environment
- ✅ **Platform Independence**: Works across Windows, Linux, macOS
- ✅ **User Flexibility**: Users can customize all directories and paths
- ✅ **Clear Error Messages**: Specific guidance when configuration missing

### **Automation Patterns**:
- ✅ **Auto-Detection**: Finds installations automatically
- ✅ **Smart Defaults**: Platform-appropriate default values
- ✅ **One-Command Setup**: Complete configuration and startup
- ✅ **Comprehensive Testing**: Validates all aspects of the system

### **User Experience Patterns**:
- ✅ **Interactive Setup**: Guided configuration process
- ✅ **Status Feedback**: Clear visual feedback throughout setup
- ✅ **Error Recovery**: Helpful error messages and solutions
- ✅ **Documentation Integration**: Setup scripts link to documentation

These patterns ensure ShadowSeek can be deployed on any system with minimal user intervention while maintaining professional quality and comprehensive validation. 