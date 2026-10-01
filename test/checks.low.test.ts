import { describe, expect, it } from "vitest";
import { lowChecks } from "../src/checks/low.js";
import { detect, file } from "./helpers.js";

const checkById = (id: string) => {
  const check = lowChecks.find((c) => c.id === id);
  if (!check) throw new Error(`check not found: ${id}`);
  return check;
};

describe("low checks", () => {
  it("no-login-rate-limit: flags a login route with no rate limiter in the file", () => {
    const check = checkById("no-login-rate-limit");
    const vulnerable = file("src/routes/auth.ts", 'router.post("/login", loginHandler)');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("no-login-rate-limit: does not flag a login route guarded by rate limiting", () => {
    const check = checkById("no-login-rate-limit");
    const clean = file(
      "src/routes/auth.ts",
      'import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 900000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("sensitive-data-in-logs: flags a password logged to the console", () => {
    const check = checkById("sensitive-data-in-logs");
    const vulnerable = file("src/routes/auth.ts", 'console.log("login attempt", { email, password })');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("sensitive-data-in-logs: does not flag a log without sensitive fields", () => {
    const check = checkById("sensitive-data-in-logs");
    const clean = file("src/routes/auth.ts", 'console.log("login attempt", { email })');
    expect(detect(check, clean)).toHaveLength(0);
  });

  describe("Python", () => {
    it("no-login-rate-limit: flags a Flask login route with no rate limiter in the file", () => {
      const check = checkById("no-login-rate-limit");
      const vulnerable = file(
        "app/routes.py",
        '@app.route("/login", methods=["POST"])\ndef login():\n    ...'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("no-login-rate-limit: does not flag a login route guarded by Flask-Limiter", () => {
      const check = checkById("no-login-rate-limit");
      const clean = file(
        "app/routes.py",
        'from flask_limiter import Limiter\nlimiter = Limiter(app)\n\n@app.route("/login", methods=["POST"])\n@limiter.limit("5/15minutes")\ndef login():\n    ...'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("no-login-rate-limit autofix: inserts a self-contained decorator right below @app.route", () => {
      const check = checkById("no-login-rate-limit");
      const vulnerable = file(
        "app/routes.py",
        '@app.route("/login", methods=["POST"])\ndef login():\n    ...'
      );
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("def __jojox_rate_limit(view):");
      expect(fixed).toContain('@app.route("/login", methods=["POST"])\n@__jojox_rate_limit\ndef login():');
    });

    it("sensitive-data-in-logs: flags a password logged with print()", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("app/auth.py", 'print("login attempt", email, password)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sensitive-data-in-logs: flags a password logged with logging.info()", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("app/auth.py", 'logging.info("login attempt email=%s password=%s", email, password)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sensitive-data-in-logs: does not flag a log without sensitive fields", () => {
      const check = checkById("sensitive-data-in-logs");
      const clean = file("app/auth.py", 'print("login attempt", email)');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("sensitive-data-in-logs: does not flag a line already commented out with #", () => {
      const check = checkById("sensitive-data-in-logs");
      const clean = file("app/auth.py", '# print("login attempt", password)');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("sensitive-data-in-logs autofix: comments the line out with #, not //", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("app/auth.py", 'print("login attempt", password)');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('# print("login attempt", password)  # rimossa da JoJoX');
    });
  });

  describe("Go", () => {
    it("no-login-rate-limit: flags a Gin login route (uppercase POST) with no rate limiter in the file", () => {
      const check = checkById("no-login-rate-limit");
      const vulnerable = file("main.go", 'router.POST("/login", loginHandler)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("no-login-rate-limit: does not flag a login route guarded by a rate limiter", () => {
      const check = checkById("no-login-rate-limit");
      const clean = file(
        "main.go",
        'limiter := tollbooth.NewLimiter(1, nil)\nrouter.POST("/login", tollbooth_gin.LimitHandler(limiter), loginHandler)'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("no-login-rate-limit autofix: does not attempt a fix (needs sync.Mutex / import merging we can't do safely)", () => {
      const check = checkById("no-login-rate-limit");
      const vulnerable = file("main.go", 'router.POST("/login", loginHandler)');
      expect(check.autofix?.(vulnerable)).toBeNull();
    });

    it("sensitive-data-in-logs: flags a password logged with log.Printf", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("main.go", 'log.Printf("login attempt email=%s password=%s", email, password)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sensitive-data-in-logs: flags a token logged with fmt.Println", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("main.go", 'fmt.Println("issued token", token)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sensitive-data-in-logs: does not flag a log without sensitive fields", () => {
      const check = checkById("sensitive-data-in-logs");
      const clean = file("main.go", 'log.Println("login attempt", email)');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("sensitive-data-in-logs: does not flag a line already commented out with //", () => {
      const check = checkById("sensitive-data-in-logs");
      const clean = file("main.go", '// log.Println("login attempt", password)');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("sensitive-data-in-logs autofix: comments the line out with //", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("main.go", 'log.Println("login attempt", password)');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('// log.Println("login attempt", password)  // rimossa da JoJoX');
    });
  });

  describe("Java", () => {
    it("no-login-rate-limit: flags a Spring @PostMapping login route with no rate limiter in the file", () => {
      const check = checkById("no-login-rate-limit");
      const vulnerable = file("AuthController.java", '@PostMapping("/login")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("no-login-rate-limit: does not flag a login route guarded by a rate limiter", () => {
      const check = checkById("no-login-rate-limit");
      const clean = file(
        "AuthController.java",
        '@RateLimiter(name = "login")\n@PostMapping("/login")'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("no-login-rate-limit autofix: does not attempt a fix (needs correct synchronization across threads)", () => {
      const check = checkById("no-login-rate-limit");
      const vulnerable = file("AuthController.java", '@PostMapping("/login")');
      expect(check.autofix?.(vulnerable)).toBeNull();
    });

    it("sensitive-data-in-logs: flags a password logged with System.out.println", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("AuthController.java", 'System.out.println("login attempt email=" + email + " password=" + password);');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sensitive-data-in-logs: flags a token logged with SLF4J's log.info", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("AuthController.java", 'log.info("issued token {}", token);');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sensitive-data-in-logs: does not flag a log without sensitive fields", () => {
      const check = checkById("sensitive-data-in-logs");
      const clean = file("AuthController.java", 'log.info("login attempt email={}", email);');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("sensitive-data-in-logs: does not flag a line already commented out with //", () => {
      const check = checkById("sensitive-data-in-logs");
      const clean = file("AuthController.java", '// log.info("login attempt password={}", password);');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("sensitive-data-in-logs autofix: comments the line out with //", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("AuthController.java", 'log.info("login attempt password={}", password);');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('// log.info("login attempt password={}", password);  // rimossa da JoJoX');
    });
  });
});