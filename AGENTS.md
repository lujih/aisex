# AGENTS.md

This file contains guidelines and commands for agentic coding agents working in this repository.

## Project Overview

This is a Cloudflare Workers + D1 (SQLite) application called "Secret Garden" - a privacy-focused personal activity tracking tool. The project uses a single-file architecture with all backend API and frontend code contained in `worker.js`.

## Build/Lint/Test Commands

### Deployment Commands
```bash
# Install Wrangler CLI
npm install -g wrangler

# Authenticate with Cloudflare
npx wrangler login

# Create D1 database
npx wrangler d1 create aisex

# Initialize database schema
npx wrangler d1 execute aisex --remote --file=schema.sql

# Set required secrets
npx wrangler secret put JWT_SECRET
npx wrangler secret put ADMIN_PASSWORD

# Deploy to production
npx wrangler deploy
```

### Development Commands
```bash
# Local development (no build process)
# Simply edit worker.js and redeploy

# Database operations
npx wrangler d1 execute aisex --local --file=schema.sql
npx wrangler d1 query aisex "SELECT * FROM users LIMIT 10"
```

## Code Style Guidelines

### JavaScript/TypeScript Style
- Use `const` by default, `let` only when reassignment is needed
- Use arrow functions for callbacks and short functions
- Use async/await for all asynchronous operations
- Use template literals for string concatenation
- Use destructuring for object/array extraction
- Use optional chaining (`?.`) and nullish coalescing (`??`)

### Import/Export Patterns
- No external dependencies (pure vanilla JavaScript)
- Use named exports for utility functions
- Group related functions together
- Place constants and configuration at the top

### Naming Conventions
- **Variables/Functions**: camelCase (e.g., `generateReqId`, `verifyAuth`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `CORS_HEADERS`, `TR_MAP`)
- **Database Tables**: snake_case (e.g., `record_acts`, `records_fts`)
- **API Endpoints**: kebab-case (e.g., `/api/auth/login`, `/api/records`)
- **File Names**: kebab-case (e.g., `worker.js`, `schema.sql`)

### Error Handling
- Use try-catch blocks for all async operations
- Return consistent error response format:
```javascript
{
  "error": "Error message",
  "code": 400
}
```
- Log errors with request ID for debugging
- Validate all user inputs before processing

### Database Patterns
- Use prepared statements for all SQL queries
- Use parameterized queries to prevent SQL injection
- Handle database connection errors gracefully
- Use transactions for multi-step operations
- Implement proper foreign key constraints

### Security Guidelines
- Always verify JWT tokens for protected endpoints
- Use PBKDF2 for password hashing with unique salts
- Never log sensitive data (passwords, tokens, secrets)
- Implement proper CORS headers
- Validate all user inputs and sanitize data
- Use HTTPS for all communications

### API Design Patterns
- RESTful endpoint structure
- Consistent JSON response format
- Use HTTP status codes appropriately
- Include request ID in logs for tracing
- Implement proper rate limiting (if needed)
- Use JSON for all request/response bodies

### Frontend Patterns (in worker.js)
- Use vanilla JavaScript (no frameworks)
- Implement progressive enhancement
- Use responsive design principles
- Optimize for mobile performance
- Implement offline capabilities where appropriate
- Use Chart.js for data visualization
- Use Three.js for 3D visualizations

### Code Organization
- Group related functions together
- Place utility functions at the top
- Use clear section comments (// --- Section ---)
- Keep functions small and focused
- Use meaningful variable names
- Add comments for complex business logic

### Performance Guidelines
- Use edge caching where appropriate
- Implement efficient database queries
- Use virtual scrolling for large lists
- Optimize image sizes and formats
- Minimize JavaScript bundle size
- Use service worker caching strategies

## Important Notes

- This is a single-file application - all changes must be made in `worker.js`
- No build process - deploy directly after editing
- Database schema is in `schema.sql` - keep it synchronized with code changes
- Always test authentication and authorization flows
- Test on mobile devices for responsive design
- Use the admin dashboard for system management
- Never commit secrets or sensitive data to version control

## Debugging Tips

- Check Cloudflare Workers logs for errors
- Use request IDs to trace requests through the system
- Test database queries locally before deploying
- Verify JWT token generation and validation
- Test CORS headers with different origins
- Use browser developer tools for frontend debugging
- Check database schema triggers and views

## Common Issues

- Database not initialized: Run schema.sql with `npx wrangler d1 execute`
- Authentication failures: Check JWT_SECRET and ADMIN_PASSWORD
- CORS errors: Verify CORS headers are properly set
- Search not working: Check FTS5 virtual table and triggers
- Deployment failures: Check wrangler.toml configuration