using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Xunit;

namespace Vefa.CustomAuth.AspNetCore.Tests;

internal sealed record AntiforgeryTokens(string Cookie, string FormFieldName, string RequestToken);

internal static class AntiforgeryTestHelpers
{
    /// <summary>
    /// Maps a minimal GET stub at <paramref name="path"/> that issues an antiforgery
    /// cookie and emits the request token inside a hidden form field. Tests use this
    /// to obtain credentials for POSTing to <c>/login</c> now that the library no
    /// longer ships a rendered login page.
    /// </summary>
    public static IEndpointRouteBuilder MapAntiforgeryStub(this IEndpointRouteBuilder endpoints, string path = "/login")
    {
        endpoints.MapGet(path, (HttpContext context, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);
            var html = $"<!doctype html><form method=\"post\" action=\"{path}\"><input type=\"hidden\" name=\"{tokens.FormFieldName}\" value=\"{tokens.RequestToken}\" /></form>";
            return Results.Content(html, "text/html");
        });
        return endpoints;
    }

    public static async Task<AntiforgeryTokens> GetAntiforgeryAsync(HttpClient client)
    {
        var response = await client.GetAsync("/login");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        var setCookieHeaders = response.Headers.GetValues("Set-Cookie");
        var cookieHeader = setCookieHeaders.Single(c => c.StartsWith(".AspNetCore.Antiforgery", StringComparison.Ordinal));
        var cookie = cookieHeader.Split(';', 2)[0];

        var fieldName = FindHiddenInputName(html, prefix: "__RequestVerificationToken")
            ?? FindFirstNonReturnUrlHiddenName(html);
        var token = ExtractHiddenInputValue(html, fieldName);
        return new AntiforgeryTokens(cookie, fieldName, token);
    }

    private static string? FindHiddenInputName(string html, string prefix)
    {
        const string marker = "name=\"";
        var idx = 0;
        while ((idx = html.IndexOf(marker, idx, StringComparison.Ordinal)) >= 0)
        {
            var start = idx + marker.Length;
            var end = html.IndexOf('"', start);
            var name = html[start..end];
            if (name.StartsWith(prefix, StringComparison.Ordinal))
            {
                return name;
            }
            idx = end + 1;
        }
        return null;
    }

    private static string FindFirstNonReturnUrlHiddenName(string html)
    {
        const string marker = "<input type=\"hidden\" name=\"";
        var idx = 0;
        while ((idx = html.IndexOf(marker, idx, StringComparison.Ordinal)) >= 0)
        {
            var start = idx + marker.Length;
            var end = html.IndexOf('"', start);
            var name = html[start..end];
            if (!string.Equals(name, "returnUrl", StringComparison.Ordinal))
            {
                return name;
            }
            idx = end + 1;
        }
        throw new InvalidOperationException("No anti-forgery hidden input found in login form.");
    }

    private static string ExtractHiddenInputValue(string html, string fieldName)
    {
        var marker = $"name=\"{fieldName}\" value=\"";
        var idx = html.IndexOf(marker, StringComparison.Ordinal);
        if (idx < 0)
        {
            var nameIdx = html.IndexOf($"name=\"{fieldName}\"", StringComparison.Ordinal);
            Assert.True(nameIdx >= 0, $"Field {fieldName} not found in login form.");
            marker = "value=\"";
            idx = html.IndexOf(marker, nameIdx, StringComparison.Ordinal);
        }
        Assert.True(idx >= 0, $"Value for {fieldName} not found.");
        var start = idx + marker.Length;
        var end = html.IndexOf('"', start);
        return html[start..end];
    }

    public static async Task<AntiforgeryTokens> GetAdminUiAntiforgeryAsync(HttpClient client, string prefix = "/customauth")
    {
        var response = await client.GetAsync(prefix + "/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        var setCookieHeaders = response.Headers.GetValues("Set-Cookie");
        var cookieHeader = setCookieHeaders.Single(c => c.StartsWith(".AspNetCore.Antiforgery", StringComparison.Ordinal));
        var cookie = cookieHeader.Split(';', 2)[0];

        const string marker = "<meta name=\"csrf-token\" content=\"";
        var idx = html.IndexOf(marker, StringComparison.Ordinal);
        if (idx < 0)
        {
            throw new InvalidOperationException("No csrf-token meta tag found in Admin UI.");
        }
        var start = idx + marker.Length;
        var end = html.IndexOf('"', start);
        var token = html[start..end];
        return new AntiforgeryTokens(cookie, "RequestVerificationToken", token);
    }
}
