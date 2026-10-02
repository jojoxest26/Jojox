import { describe, expect, it } from "vitest";
import { mediumChecks } from "../src/checks/medium.js";
import { detect, file } from "./helpers.js";

const checkById = (id: string) => {
  const check = mediumChecks.find((c) => c.id === id);
  if (!check) throw new Error(`check not found: ${id}`);
  return check;
};

describe("medium checks", () => {
  it("xss-dangerous-html: flags dangerouslySetInnerHTML", () => {
    const check = checkById("xss-dangerous-html");
    const vulnerable = file(
      "src/Comment.tsx",
      "<div dangerouslySetInnerHTML={{ __html: comment.text }} />"
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("xss-dangerous-html: does not flag plain JSX text content", () => {
    const check = checkById("xss-dangerous-html");
    const clean = file("src/Comment.tsx", "<div>{comment.text}</div>");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("public-storage-bucket: flags a bucket created as public", () => {
    const check = checkById("public-storage-bucket");
    const vulnerable = file("src/storage.ts", 'supabase.storage.createBucket("uploads", { public: true })');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("public-storage-bucket: does not flag a private bucket", () => {
    const check = checkById("public-storage-bucket");
    const clean = file("src/storage.ts", 'supabase.storage.createBucket("uploads", { public: false })');
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("csrf-state-changing-get: flags a GET route that deletes data", () => {
    const check = checkById("csrf-state-changing-get");
    const vulnerable = file("src/routes/posts.ts", 'router.get("/posts/:id/delete", deletePost)');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("csrf-state-changing-get: does not flag a POST route", () => {
    const check = checkById("csrf-state-changing-get");
    const clean = file(
      "src/routes/posts.ts",
      'router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("insecure-token-storage: flags a token saved to localStorage", () => {
    const check = checkById("insecure-token-storage");
    const vulnerable = file("src/auth.ts", 'localStorage.setItem("authToken", token)');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("insecure-token-storage: does not flag an httpOnly cookie", () => {
    const check = checkById("insecure-token-storage");
    const clean = file(
      "src/auth.ts",
      'res.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("open-redirect: flags a redirect built from unsanitized query input", () => {
    const check = checkById("open-redirect");
    const vulnerable = file("src/routes/auth.ts", "res.redirect(req.query.next)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("open-redirect: does not flag a redirect validated against an allowlist", () => {
    const check = checkById("open-redirect");
    const clean = file(
      "src/routes/auth.ts",
      'const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("idor: flags a lookup by params.id with no ownership check nearby", () => {
    const check = checkById("idor");
    const vulnerable = file("src/routes/orders.ts", "const order = await Order.findById(req.params.id)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("idor: does not flag when an ownership check follows the lookup", () => {
    const check = checkById("idor");
    const clean = file(
      "src/routes/orders.ts",
      'const order = await Order.findById(req.params.id)\nif (order.userId !== req.user.id) throw new Error("Forbidden")'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  describe("Python", () => {
    it("xss-dangerous-html: flags Jinja2's |safe filter", () => {
      const check = checkById("xss-dangerous-html");
      const vulnerable = file("templates/comment.html", "{{ comment.text|safe }}");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("xss-dangerous-html: flags Django's mark_safe()", () => {
      const check = checkById("xss-dangerous-html");
      const vulnerable = file("app/views.py", "return mark_safe(comment.text)");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("xss-dangerous-html: does not flag plain Jinja2 output (auto-escaped by default)", () => {
      const check = checkById("xss-dangerous-html");
      const clean = file("templates/comment.html", "{{ comment.text }}");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("public-storage-bucket: flags a supabase-py bucket created as public (capital True)", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file("app/storage.py", 'supabase.storage.create_bucket("uploads", {"public": True})');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: flags a boto3 S3 object made public", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file("app/storage.py", 's3.put_object(Bucket="uploads", Key=key, ACL="public-read")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: does not flag a private supabase-py bucket", () => {
      const check = checkById("public-storage-bucket");
      const clean = file("app/storage.py", 'supabase.storage.create_bucket("uploads", {"public": False})');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("csrf-state-changing-get: flags a Flask route that deletes data with no explicit POST method", () => {
      const check = checkById("csrf-state-changing-get");
      const vulnerable = file("app/routes.py", '@app.route("/posts/<id>/delete")\ndef delete_post(id):\n    ...');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("csrf-state-changing-get: does not flag a Flask route restricted to POST", () => {
      const check = checkById("csrf-state-changing-get");
      const clean = file(
        "app/routes.py",
        '@app.route("/posts/<id>/delete", methods=["POST"])\ndef delete_post(id):\n    ...'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("open-redirect: flags a Flask redirect built from request.args", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("app/auth.py", "return redirect(request.args['next'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: flags a Django HttpResponseRedirect built from request.GET", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("app/views.py", "return HttpResponseRedirect(request.GET['next'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: does not flag a redirect to a fixed path", () => {
      const check = checkById("open-redirect");
      const clean = file("app/auth.py", 'return redirect("/dashboard")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("open-redirect autofix: replaces the Flask redirect with a fixed one, commented in Python style", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("app/auth.py", "return redirect(request.args['next'])");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('redirect("/")');
      expect(fixed).toContain("# JoJoX:");
      expect(fixed).not.toContain("/*");
    });

    it("idor: flags a Django ORM lookup by request.GET id with no ownership check nearby", () => {
      const check = checkById("idor");
      const vulnerable = file("app/views.py", "order = Order.objects.get(pk=request.GET['id'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("idor: flags get_object_or_404 with no ownership check nearby", () => {
      const check = checkById("idor");
      const vulnerable = file("app/views.py", "order = get_object_or_404(Order, pk=request.GET['id'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("idor: does not flag when an ownership check follows the lookup", () => {
      const check = checkById("idor");
      const clean = file(
        "app/views.py",
        "order = Order.objects.get(pk=request.GET['id'])\nif order.user_id != request.user.id:\n    raise PermissionDenied"
      );
      expect(detect(check, clean)).toHaveLength(0);
    });
  });

  describe("Go", () => {
    it("xss-dangerous-html: flags html/template's template.HTML()", () => {
      const check = checkById("xss-dangerous-html");
      const vulnerable = file("main.go", "data.Comment = template.HTML(comment.Text)");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: flags an AWS SDK for Go object made public", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file(
        "main.go",
        '_, err := svc.PutObject(&s3.PutObjectInput{Bucket: aws.String("uploads"), ACL: aws.String("public-read")})'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: does not flag a private AWS SDK for Go object", () => {
      const check = checkById("public-storage-bucket");
      const clean = file(
        "main.go",
        '_, err := svc.PutObject(&s3.PutObjectInput{Bucket: aws.String("uploads"), ACL: aws.String("private")})'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("public-storage-bucket autofix: replaces aws.String(\"public-read\") with aws.String(\"private\")", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file("main.go", 'ACL: aws.String("public-read")');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe('ACL: aws.String("private")');
    });

    it("csrf-state-changing-get: flags a Gin route (uppercase GET) that deletes data", () => {
      const check = checkById("csrf-state-changing-get");
      const vulnerable = file("main.go", 'router.GET("/posts/:id/delete", deletePost)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: flags a Gin redirect built from c.Query", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("main.go", 'c.Redirect(http.StatusFound, c.Query("next"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: flags a net/http redirect built from r.FormValue", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("main.go", 'http.Redirect(w, r, r.FormValue("next"), http.StatusFound)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: does not flag a redirect to a fixed path", () => {
      const check = checkById("open-redirect");
      const clean = file("main.go", 'c.Redirect(http.StatusFound, "/dashboard")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("open-redirect autofix: replaces the Gin redirect with a fixed one, commented in Go style", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("main.go", 'c.Redirect(http.StatusFound, c.Query("next"))');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('c.Redirect(http.StatusFound, "/")');
      expect(fixed).toContain("// JoJoX:");
    });

    it("idor: flags a GORM lookup by Gin's c.Param id with no ownership check nearby", () => {
      const check = checkById("idor");
      const vulnerable = file("main.go", 'db.First(&order, c.Param("id"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("idor: does not flag when an ownership check (UserID) follows the lookup", () => {
      const check = checkById("idor");
      const clean = file(
        "main.go",
        'db.First(&order, c.Param("id"))\nif order.UserID != currentUser.ID {\n  panic("forbidden")\n}'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });
  });

  describe("Java", () => {
    it("xss-dangerous-html: flags Thymeleaf's th:utext", () => {
      const check = checkById("xss-dangerous-html");
      const vulnerable = file("comment.html", '<div th:utext="${comment.text}"></div>');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("xss-dangerous-html: does not flag Thymeleaf's escaped th:text", () => {
      const check = checkById("xss-dangerous-html");
      const clean = file("comment.html", '<div th:text="${comment.text}"></div>');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("public-storage-bucket: flags an AWS SDK for Java (v1) object made public", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file(
        "StorageService.java",
        "s3.putObject(new PutObjectRequest(bucket, key, file).withCannedAcl(CannedAccessControlList.PublicRead));"
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: flags an AWS SDK for Java (v2) object made public", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file(
        "StorageService.java",
        "PutObjectRequest.builder().bucket(bucket).key(key).acl(ObjectCannedACL.PUBLIC_READ).build();"
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: does not flag a private AWS SDK for Java object", () => {
      const check = checkById("public-storage-bucket");
      const clean = file(
        "StorageService.java",
        "s3.putObject(new PutObjectRequest(bucket, key, file).withCannedAcl(CannedAccessControlList.Private));"
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("public-storage-bucket autofix: replaces CannedAccessControlList.PublicRead with .Private", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file("StorageService.java", "CannedAccessControlList.PublicRead");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe("CannedAccessControlList.Private");
    });

    it("public-storage-bucket autofix: replaces ObjectCannedACL.PUBLIC_READ with .PRIVATE", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file("StorageService.java", "ObjectCannedACL.PUBLIC_READ");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe("ObjectCannedACL.PRIVATE");
    });

    it("csrf-state-changing-get: flags a Spring @GetMapping route that deletes data", () => {
      const check = checkById("csrf-state-changing-get");
      const vulnerable = file("PostController.java", '@GetMapping("/posts/{id}/delete")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("csrf-state-changing-get: does not flag a @PostMapping route", () => {
      const check = checkById("csrf-state-changing-get");
      const clean = file("PostController.java", '@PostMapping("/posts/{id}/delete")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("open-redirect: flags a Servlet redirect built from request.getParameter", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("AuthServlet.java", 'response.sendRedirect(request.getParameter("next"));');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: does not flag a redirect to a fixed path", () => {
      const check = checkById("open-redirect");
      const clean = file("AuthServlet.java", 'response.sendRedirect("/dashboard");');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("open-redirect autofix: replaces the Servlet redirect with a fixed one, using a block comment (Java has no automatic semicolon insertion)", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("AuthServlet.java", 'response.sendRedirect(request.getParameter("next"));');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('response.sendRedirect("/")');
      expect(fixed).toContain("/* JoJoX:");
      expect(fixed).toContain("*/;");
    });

    it("idor: flags a Spring Data JPA findById by request.getParameter id with no ownership check nearby", () => {
      const check = checkById("idor");
      const vulnerable = file("OrderController.java", 'Order order = orderRepository.findById(request.getParameter("id"));');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("idor: flags a findById wrapped in Long.parseLong", () => {
      const check = checkById("idor");
      const vulnerable = file(
        "OrderController.java",
        'Order order = orderRepository.findById(Long.parseLong(request.getParameter("id")));'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("idor: does not flag when an ownership check (getPrincipal) follows the lookup", () => {
      const check = checkById("idor");
      const clean = file(
        "OrderController.java",
        'Order order = orderRepository.findById(request.getParameter("id"));\nif (!order.getUserId().equals(auth.getPrincipal())) throw new ForbiddenException();'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });
  });

  describe("PHP", () => {
    it("xss-dangerous-html: flags Laravel Blade's unescaped {!! !!}", () => {
      const check = checkById("xss-dangerous-html");
      const vulnerable = file("comment.blade.php", "{!! $comment->text !!}");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("xss-dangerous-html: does not flag Blade's escaped {{ }}", () => {
      const check = checkById("xss-dangerous-html");
      const clean = file("comment.blade.php", "{{ $comment->text }}");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("public-storage-bucket: flags an AWS SDK for PHP object made public", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file(
        "StorageService.php",
        "$s3->putObject(['Bucket' => $bucket, 'Key' => $key, 'ACL' => 'public-read']);"
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: does not flag a private AWS SDK for PHP object", () => {
      const check = checkById("public-storage-bucket");
      const clean = file(
        "StorageService.php",
        "$s3->putObject(['Bucket' => $bucket, 'Key' => $key, 'ACL' => 'private']);"
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("public-storage-bucket autofix: replaces 'ACL' => 'public-read' with 'ACL' => 'private'", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file("StorageService.php", "'ACL' => 'public-read'");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe("'ACL' => 'private'");
    });

    it("csrf-state-changing-get: flags a Laravel Route::get route that deletes data", () => {
      const check = checkById("csrf-state-changing-get");
      const vulnerable = file("routes/web.php", "Route::get('/posts/{id}/delete', 'PostController@delete');");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("csrf-state-changing-get: does not flag a Route::post route", () => {
      const check = checkById("csrf-state-changing-get");
      const clean = file("routes/web.php", "Route::post('/posts/{id}/delete', 'PostController@delete');");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("open-redirect: flags a header Location redirect built with concatenation", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("auth.php", "header('Location: ' . $_GET['next']);");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: flags a header Location redirect with a variable interpolated in a double-quoted string", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("auth.php", 'header("Location: $_GET[\'next\']");');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: does not flag a redirect to a fixed path", () => {
      const check = checkById("open-redirect");
      const clean = file("auth.php", "header('Location: /dashboard');");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("open-redirect autofix: replaces the header redirect with a fixed one, using a block comment (PHP has no automatic semicolon insertion)", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("auth.php", "header('Location: ' . $_GET['next']);");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('header("Location: /")');
      expect(fixed).toContain("/* JoJoX:");
      expect(fixed).toContain("*/;");
    });

    it("idor: flags a Laravel Eloquent find by $_GET id with no ownership check nearby", () => {
      const check = checkById("idor");
      const vulnerable = file("OrderController.php", "$order = Order::find($_GET['id']);");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("idor: flags findOrFail with $request->input", () => {
      const check = checkById("idor");
      const vulnerable = file("OrderController.php", "$order = Order::findOrFail($request->input('id'));");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("idor: does not flag when an ownership check (Auth::id) follows the lookup", () => {
      const check = checkById("idor");
      const clean = file(
        "OrderController.php",
        "$order = Order::find($_GET['id']);\nif ($order->user_id !== Auth::id()) abort(403);"
      );
      expect(detect(check, clean)).toHaveLength(0);
    });
  });

  describe("Punto 13 — header injection (CRLF / response splitting)", () => {
    it("flags res.setHeader built from req.query", () => {
      const check = checkById("header-injection");
      const vulnerable = file("src/routes.ts", 'res.setHeader("X-Reason", req.query.reason)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("does not flag res.setHeader with a fixed value", () => {
      const check = checkById("header-injection");
      const clean = file("src/routes.ts", 'res.setHeader("X-Reason", "ok")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("Python: flags response.headers[...] assigned from Flask request.args", () => {
      const check = checkById("header-injection");
      const vulnerable = file("app/views.py", "response.headers['X-Reason'] = request.args['reason']");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("Go: flags Gin's c.Header built from c.Query", () => {
      const check = checkById("header-injection");
      const vulnerable = file("main.go", 'c.Header("X-Reason", c.Query("reason"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("Go: flags net/http's w.Header().Set built from r.FormValue", () => {
      const check = checkById("header-injection");
      const vulnerable = file("main.go", 'w.Header().Set("X-Reason", r.FormValue("reason"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("Java: flags response.setHeader built from request.getParameter", () => {
      const check = checkById("header-injection");
      const vulnerable = file("Controller.java", 'response.setHeader("X-Reason", request.getParameter("reason"));');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("PHP: flags a custom header built with string concatenation", () => {
      const check = checkById("header-injection");
      const vulnerable = file("page.php", "header('X-Reason: ' . $_GET['reason']);");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("PHP: flags a custom header with a variable interpolated in a double-quoted string", () => {
      const check = checkById("header-injection");
      const vulnerable = file("page.php", 'header("X-Reason: $_GET[\'reason\']");');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("PHP: does not flag a fixed header value", () => {
      const check = checkById("header-injection");
      const clean = file("page.php", "header('X-Reason: ok');");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("PHP: does not double-flag a Location header built from $_GET — that's open-redirect's job, not header-injection's", () => {
      const headerInjection = checkById("header-injection");
      const openRedirect = mediumChecks.find((c) => c.id === "open-redirect")!;
      const vulnerable = file("auth.php", "header('Location: ' . $_GET['next']);");
      expect(detect(headerInjection, vulnerable)).toHaveLength(0);
      expect(detect(openRedirect, vulnerable)).toHaveLength(1);
    });
  });

  describe("Fase 2 — IaC (Dockerfile)", () => {
    it("docker-missing-user: flags a Dockerfile with no USER instruction", () => {
      const check = checkById("docker-missing-user");
      const vulnerable = file("Dockerfile", 'FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]\n');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("docker-missing-user: does not flag a Dockerfile that sets USER", () => {
      const check = checkById("docker-missing-user");
      const clean = file("Dockerfile", 'FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]\n');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("docker-missing-user: does not flag a multi-stage build that sets USER only in the final stage", () => {
      const check = checkById("docker-missing-user");
      const clean = file(
        "Dockerfile",
        'FROM node:20-slim AS builder\nWORKDIR /app\nCOPY . .\nRUN npm run build\n\nFROM node:20-slim\nWORKDIR /app\nCOPY --from=builder /app/dist ./dist\nUSER node\nCMD ["node", "dist/server.js"]\n'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("docker-missing-user: does not flag a file with no FROM instruction (not a real Dockerfile build stage)", () => {
      const check = checkById("docker-missing-user");
      const clean = file("Dockerfile", "# just a comment\n");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("docker-missing-user: does not flag anything in a file that isn't a Dockerfile", () => {
      const check = checkById("docker-missing-user");
      const clean = file("notes.txt", "FROM node:20-slim\n");
      expect(detect(check, clean)).toHaveLength(0);
    });
  });
});