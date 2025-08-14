# ShadowSeek Multi-Provider AI Setup Guide

## 🤖 AI Provider Support

ShadowSeek now supports four major AI providers for enhanced binary analysis:

- **OpenAI (GPT-3.5/GPT-4)** - Most tested and recommended
- **Anthropic Claude** - Excellent for security analysis
- **Google Gemini** - Fast and cost-effective
- **Ollama (Local)** - Privacy-focused local inference

## 📦 Installation

### 1. Install Required Dependencies

```bash
# Install all AI provider packages using uv (recommended)
uv add anthropic>=0.7.0 google-generativeai>=0.3.0

# Note: OpenAI is already included in the base dependencies
# If you need to add it manually: uv add openai>=1.0.0
```

### 2. Obtain API Keys

#### OpenAI (Recommended)
1. Visit https://platform.openai.com/
2. Create an account and navigate to API Keys
3. Create a new API key
4. Copy the key (starts with `sk-`)

#### Anthropic Claude
1. Visit https://console.anthropic.com/
2. Create an account and navigate to API Keys
3. Create a new API key
4. Copy the key (starts with `sk-ant-`)

#### Google Gemini
1. Visit https://ai.google.dev/
2. Create a Google AI Studio account
3. Generate an API key
4. Copy the key

#### Ollama (Local)
1. Install Ollama from https://ollama.ai/
2. Start Ollama service: `ollama serve`
3. Download a model: `ollama pull llama2`
4. No API key required - runs locally

### 3. Configure Environment Variables

Add the following to your `.env` file:

```bash
# Primary AI provider selection
LLM_PROVIDER=openai  # Options: openai, claude, gemini, ollama

# OpenAI Configuration
OPENAI_API_KEY=sk-your-openai-key-here
OPENAI_MODEL=gpt-3.5-turbo  # Options: gpt-3.5-turbo, gpt-4, gpt-4-turbo

# Claude Configuration  
CLAUDE_API_KEY=sk-ant-your-claude-key-here
CLAUDE_MODEL=claude-3-5-sonnet-20241022  # Options: claude-3-5-sonnet-20241022, claude-3-7-sonnet-20250219, claude-sonnet-4-20250514

# Gemini Configuration
GEMINI_API_KEY=your-gemini-key-here
GEMINI_MODEL=gemini-2.5-flash  # Options: gemini-2.5-flash, gemini-2.5-pro, gemini-2.0-flash

# Ollama Configuration (Local - No API Key Required)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama2  # Options: llama2, codellama, mistral, llama3, etc.

# AI Service Settings (Optional)
LLM_TIMEOUT=60
LLM_MAX_TOKENS=3000
LLM_TEMPERATURE=0.2
```

## ⚙️ Configuration via Web Interface

1. Navigate to http://localhost:3000/config
2. Select the "AI/LLM Settings" tab
3. Choose your primary provider from the dropdown
4. Enter API keys for the providers you want to use
5. Configure models and settings
6. Test each connection using the "Test Connection" button
7. Save configuration

## 🧪 Testing Your Setup

### Via Web Interface
- Go to http://localhost:3000/config
- Click "Test Connection" for each provider you've configured
- Look for green success messages

### Via API
```bash
# Test OpenAI
curl -X POST http://localhost:5000/api/config/test-connection \
  -H "Content-Type: application/json" \
  -d '{"provider": "openai", "api_key": "your-key", "model": "gpt-3.5-turbo"}'

# Test Claude
curl -X POST http://localhost:5000/api/config/test-connection \
  -H "Content-Type: application/json" \
  -d '{"provider": "claude", "api_key": "your-key", "model": "claude-3-5-sonnet-20241022"}'

# Test Gemini
curl -X POST http://localhost:5000/api/config/test-connection \
  -H "Content-Type: application/json" \
  -d '{"provider": "gemini", "api_key": "your-key", "model": "gemini-pro"}'

# Test Ollama (No API Key Required)
curl -X POST http://localhost:5000/api/config/test-connection \
  -H "Content-Type: application/json" \
  -d '{"provider": "ollama", "base_url": "http://localhost:11434", "model": "llama2"}'
```

### Check AI Status
```bash
curl http://localhost:5000/api/ai/status
```

## 🔄 Switching Providers

You can switch providers at any time:

1. **Via Web Interface**: 
   - Go to Configuration → AI/LLM Settings
   - Change the "Primary LLM Provider" dropdown
   - Save configuration

2. **Via Environment**:
   - Update `LLM_PROVIDER` in your `.env` file
   - Restart the application or use the reload functionality

3. **Automatic Reload**: 
   - Configuration changes via the web interface automatically reload AI services
   - No application restart required

## 🎯 Provider Recommendations

### For Security Analysis
- **Claude**: Excellent at understanding security implications and providing detailed analysis
- **GPT-4**: Most comprehensive analysis with good security awareness
- **GPT-3.5 Turbo**: Good balance of speed and quality

### For Speed
- **Ollama (Local)**: Fastest for repeated use, no API costs
- **Gemini 1.5 Flash**: Fastest cloud responses
- **GPT-3.5 Turbo**: Good speed with OpenAI reliability
- **Gemini Pro**: Good speed with Google reliability

### For Cost Efficiency
- **Ollama (Local)**: No ongoing costs, completely free after setup
- **Gemini Pro**: Most cost-effective for high-volume cloud analysis
- **GPT-3.5 Turbo**: Good balance of cost and performance
- **Claude**: Higher cost but excellent quality

### For Privacy & Security
- **Ollama (Local)**: Complete data privacy, no external API calls
- **Claude**: Strong privacy policies and security practices
- **OpenAI**: Industry-standard security with data retention policies
- **Gemini**: Google's enterprise security standards

## 🛠️ Troubleshooting

### Common Issues

#### "Failed to initialize [Provider] client"
- Check that the required package is installed: `uv add anthropic` or `uv add google-generativeai`
- Verify your API key is correct and active
- Check your internet connection

#### "API key is required" 
- Ensure the API key is set in your `.env` file
- Check that the key name matches exactly: `OPENAI_API_KEY`, `CLAUDE_API_KEY`, `GEMINI_API_KEY`
- Restart the application after adding new keys

#### "Connection test failed"
- Verify your API key has sufficient credits/quota
- Check if your IP is allowed (some providers have geographic restrictions)
- Try a different model if available

#### AI Analysis Returns Errors
- Check the AI status endpoint: `curl http://localhost:5000/api/ai/status`
- Verify the selected provider is properly configured
- Check application logs for detailed error messages

### Package Installation Issues

If you encounter issues installing the AI packages:

```bash
# For Claude
uv add anthropic --upgrade

# For Gemini  
uv add google-generativeai --upgrade

# If you get SSL errors, you may need to configure uv's index settings
# Check: uv help add for SSL configuration options
```

## 📊 Usage Examples

Once configured, all AI analysis will automatically use your selected provider:

- **Function Analysis**: AI explanations use the configured provider
- **Security Analysis**: Vulnerability detection uses the configured provider  
- **Fuzzing**: Target selection and rationale use the configured provider

The analysis quality and style may vary between providers, but all provide security-focused insights suitable for professional use.

## 🔒 Security Notes

- **API Keys**: Store securely and never commit to version control
- **Rate Limits**: Each provider has different rate limits and pricing
- **Data Privacy**: Review each provider's data handling policies
- **Local Options**: Consider Ollama for local inference if data privacy is critical

## 📞 Support

If you encounter issues with the multi-provider setup:

1. Check the logs: `tail -f logs/app.log`
2. Test each provider individually via the web interface
3. Verify your `.env` file configuration
4. Check the AI status endpoint for detailed information

The multi-provider system is fully backward compatible - existing OpenAI configurations will continue to work without changes.

## 🏠 Ollama Local Setup Guide

### Installation
```bash
# Install Ollama (macOS/Linux)
curl -fsSL https://ollama.ai/install.sh | sh

# Or download from https://ollama.ai/ for Windows
```

### Model Setup
```bash
# Start Ollama service
ollama serve

# In another terminal, download models
ollama pull llama2          # 7B general model
ollama pull codellama       # Code-focused model
ollama pull mistral         # Fast and capable
ollama pull llama3          # Latest Llama model

# List available models
ollama list
```

### ShadowSeek Configuration
```bash
# Set Ollama as primary provider
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama2  # Use any model you've downloaded
```

### Advantages of Ollama
- **Complete Privacy**: No data sent to external services
- **No API Costs**: Free to use after initial setup
- **Offline Operation**: Works without internet connection
- **Custom Models**: Use specialized security models
- **High Performance**: Optimized for local hardware 