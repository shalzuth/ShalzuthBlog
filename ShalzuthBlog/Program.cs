using AspNetStatic;
using Markdig;
using Westwind.AspNetCore.Markdown;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
builder.Services.AddMarkdown(config =>
{
    config.ConfigureMarkdigPipeline = builder =>
    {
        builder.UseEmphasisExtras(Markdig.Extensions.EmphasisExtras.EmphasisExtraOptions.Default)
            .UsePipeTables()
            .UseGridTables()
            .UseAutoIdentifiers(Markdig.Extensions.AutoIdentifiers.AutoIdentifierOptions.GitHub) // Headers get id="name" 
            .UseAutoLinks() // URLs are parsed into anchors
            .UseAbbreviations()
            .UseYamlFrontMatter()
            .UseEmojiAndSmiley(true)
            .UseListExtras()
            .UseFigures()
            .UseTaskLists()
            .UseCustomContainers()
            .UseGenericAttributes();

        //.DisableHtml();   // don't render HTML - encode as text
    };
    //config.AddMarkdownProcessingFolder("~/Index.cshtml");
});
var blogEntries = Directory.GetDirectories("BlogContent").Select(dir => new PageResource("/Blog/" + dir.Replace("BlogContent\\", "").Replace("BlogContent/", "")));
var pages = new List<ResourceInfoBase>
{
      new JsResource("/lib/highlightjs-badge.js"),
      new CssResource("/ShalzuthBlog.styles.css"),
      new CssResource("/css/site.css"),
      new BinResource("/favicon.ico"),
      new BinResource("/img/p2w_example.png"),
      new BinResource("/lucy.jpg"),
      new PageResource("/"),
}.Concat(blogEntries);
builder.Services.AddSingleton<IStaticResourcesInfoProvider>(new StaticResourcesInfoProvider(pages));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();

//app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();
app.UseMarkdown();

if (Environment.UserName.Contains("buildbot"))
{
    Directory.CreateDirectory(@"bin\static");
    app.GenerateStaticContent(@"bin\static", true);
}
app.Run();
