window.addEventListener("DOMContentLoaded", function () {
  if (typeof PagefindUI === "undefined") {
    document.getElementById("search").textContent = "Índice de busca ainda não gerado.";
    return;
  }
  new PagefindUI({ element: "#search", showSubResults: true, showImages: false,
    translations: { placeholder: "Buscar CVE, tecnologia, conceito…", zero_results: "Nada encontrado para [SEARCH_TERM]" } });
});
