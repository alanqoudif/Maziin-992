document.addEventListener("DOMContentLoaded", () => {
  if (window.jQuery && window.jQuery.fn.DataTable) {
    jQuery(".datatable").DataTable({ pageLength: 25 });
  }
});
