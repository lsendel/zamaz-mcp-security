#!/bin/bash
# Security scanning script for MCP Security module
# Runs OWASP dependency check, SonarQube analysis, and OWASP ZAP scan

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "MCP Security Module - Security Scan"
echo "=========================================="

# Check prerequisites
command -v mvn >/dev/null 2>&1 || { echo "Maven is required but not installed. Aborting." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }

cd "$PROJECT_ROOT"

# Step 1: Run tests with coverage
echo "Step 1: Running tests with coverage..."
mvn clean test jacoco:report

# Step 2: OWASP Dependency Check
echo "Step 2: Running OWASP Dependency Check..."
mvn dependency-check:check || true

# Step 3: Compile and package
echo "Step 3: Building application..."
mvn compile package -DskipTests

# Step 4: SonarQube Analysis
echo "Step 4: Running SonarQube analysis..."
if [ -z "$SONAR_HOST_URL" ]; then
    echo "Warning: SONAR_HOST_URL not set. Skipping SonarQube analysis."
    echo "To run SonarQube analysis, set:"
    echo "  export SONAR_HOST_URL=http://localhost:9000"
    echo "  export SONAR_LOGIN=your-token"
else
    mvn sonar:sonar \
        -Dsonar.host.url=$SONAR_HOST_URL \
        -Dsonar.login=$SONAR_LOGIN
fi

# Step 5: Start application for security testing
echo "Step 5: Starting application for security testing..."
java -jar target/mcp-security-*.jar \
    --spring.profiles.active=test \
    --server.port=8080 &
APP_PID=$!

# Wait for application to start
echo "Waiting for application to start..."
for i in {1..30}; do
    if curl -s http://localhost:8080/actuator/health > /dev/null; then
        echo "Application started successfully"
        break
    fi
    sleep 2
done

# Step 6: OWASP ZAP Security Scan
echo "Step 6: Running OWASP ZAP security scan..."
mkdir -p "$SCRIPT_DIR/reports"

docker run --rm \
    --network host \
    -v "$SCRIPT_DIR:/zap/wrk" \
    -t owasp/zap2docker-stable zap.sh \
    -cmd -autorun /zap/wrk/owasp-zap-scan.yaml

# Step 7: Custom security tests
echo "Step 7: Running custom security tests..."

# Test for security headers
echo "Testing security headers..."
curl -s -I http://localhost:8080/api/v1/health | grep -E "(X-Content-Type-Options|X-Frame-Options|X-XSS-Protection|Strict-Transport-Security)" || echo "Warning: Missing security headers"

# Test for rate limiting
echo "Testing rate limiting..."
for i in {1..20}; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/v1/auth/login -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test"}')
    if [ "$STATUS" = "429" ]; then
        echo "Rate limiting is working (received 429 after $i requests)"
        break
    fi
done

# Test for SQL injection
echo "Testing SQL injection protection..."
SQLI_RESPONSE=$(curl -s http://localhost:8080/api/v1/users?search="' OR '1'='1" -w "\n%{http_code}")
if [[ "$SQLI_RESPONSE" == *"400"* ]]; then
    echo "SQL injection protection is working"
else
    echo "Warning: SQL injection protection may not be working"
fi

# Test for XSS protection
echo "Testing XSS protection..."
XSS_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/auth/register \
    -H "Content-Type: application/json" \
    -d '{"username":"<script>alert(1)</script>","email":"test@test.com","password":"Test123!"}' \
    -w "\n%{http_code}")
if [[ "$XSS_RESPONSE" == *"400"* ]]; then
    echo "XSS protection is working"
else
    echo "Warning: XSS protection may not be working"
fi

# Stop application
echo "Stopping application..."
kill $APP_PID

# Step 8: Generate security report
echo "Step 8: Generating security report..."
cat > "$SCRIPT_DIR/reports/security-scan-summary.md" << EOF
# Security Scan Summary

## Date: $(date)

### Test Results

1. **Unit Tests**: $(if [ -f target/surefire-reports/TEST-*.xml ]; then echo "✅ Passed"; else echo "❌ Failed"; fi)
2. **OWASP Dependency Check**: $(if [ -f target/dependency-check-report.html ]; then echo "✅ Completed"; else echo "❌ Failed"; fi)
3. **SonarQube Analysis**: $(if [ -n "$SONAR_HOST_URL" ]; then echo "✅ Completed"; else echo "⚠️ Skipped"; fi)
4. **OWASP ZAP Scan**: $(if [ -f "$SCRIPT_DIR/reports/mcp-security-scan-report.html" ]; then echo "✅ Completed"; else echo "❌ Failed"; fi)

### Key Findings

#### Dependency Vulnerabilities
$(if [ -f target/dependency-check-report.html ]; then
    echo "See detailed report: target/dependency-check-report.html"
else
    echo "No dependency check performed"
fi)

#### Security Headers
- X-Content-Type-Options: $(curl -s -I http://localhost:8080/api/v1/health | grep -q "X-Content-Type-Options" && echo "✅ Present" || echo "❌ Missing")
- X-Frame-Options: $(curl -s -I http://localhost:8080/api/v1/health | grep -q "X-Frame-Options" && echo "✅ Present" || echo "❌ Missing")
- X-XSS-Protection: $(curl -s -I http://localhost:8080/api/v1/health | grep -q "X-XSS-Protection" && echo "✅ Present" || echo "❌ Missing")

### Recommendations

1. Review all high and critical vulnerabilities
2. Update dependencies with known vulnerabilities
3. Fix any missing security headers
4. Address any OWASP ZAP findings

### Reports

- OWASP Dependency Check: \`target/dependency-check-report.html\`
- OWASP ZAP Report: \`security-scan/reports/mcp-security-scan-report.html\`
- JaCoCo Coverage: \`target/site/jacoco/index.html\`
EOF

echo "=========================================="
echo "Security scan completed!"
echo "Summary report: $SCRIPT_DIR/reports/security-scan-summary.md"
echo "=========================================="

# Return appropriate exit code
if [ -f target/dependency-check-report.html ] && grep -q "High\|Critical" target/dependency-check-report.html; then
    echo "WARNING: High or Critical vulnerabilities found!"
    exit 1
fi

exit 0