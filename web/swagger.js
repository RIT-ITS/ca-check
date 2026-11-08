// Starts Swagger UI on /swagger. Kept out of the HTML so the page works under
// the site's CSP, which allows no inline scripts.
"use strict";
window.addEventListener("DOMContentLoaded", () => {
  const el = document.getElementById("swagger-ui");
  if (!window.SwaggerUIBundle) {
    el.textContent = "The API reference could not load. The spec is still available at openapi.json.";
    return;
  }
  window.SwaggerUIBundle({
    url: "openapi.json",
    domNode: el,
    deepLinking: true,
    presets: [window.SwaggerUIBundle.presets.apis],
    layout: "BaseLayout",
    // Don't send the spec to the public swagger.io validator.
    validatorUrl: null,
    supportedSubmitMethods: ["get", "post"],
    defaultModelsExpandDepth: 0,
    displayRequestDuration: true,
  });
});
