document.addEventListener("DOMContentLoaded", () => {
  if (window.jQuery && window.jQuery.fn.DataTable) {
    jQuery(".datatable").DataTable({ 
      pageLength: 25,
      language: {
        search: "",
        searchPlaceholder: "Search assets...",
        lengthMenu: "Show _MENU_",
        info: "Showing _START_ to _END_ of _TOTAL_ entries",
        paginate: {
          first: "«",
          last: "»",
          next: "›",
          previous: "‹"
        }
      },
      drawCallback: function() {
        // Any custom styling updates after table redraw
        jQuery('.dataTables_paginate .paginate_button').addClass('inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 border border-input bg-background hover:bg-accent hover:text-accent-foreground h-9 px-3');
      }
    });
  }
});
