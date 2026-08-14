// Example ASP.NET / C# server-rendered XSS sinks. Intentionally unsafe,
// for detector testing only.

public class ProfileController : Controller
{
    public IActionResult Show()
    {
        // HIGH: request input written straight into the response as raw HTML
        var name = Request.Query["name"];
        Response.Write("<h1>Hello " + name + "</h1>");

        // HIGH: a string marked as trusted HTML, built from user input
        var bio = Request.Form["bio"];
        var trusted = new HtmlString(bio);
        ViewData["Bio"] = trusted;

        // MEDIUM: dynamic value marked raw HTML (no traced source on this line)
        ViewBag.Comment = new MvcHtmlString(comment);

        return View();
    }
}
