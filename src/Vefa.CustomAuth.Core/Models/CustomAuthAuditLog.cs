using System;

namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents an audit log entry for security and management tracking.
/// </summary>
public sealed class CustomAuthAuditLog
{
    /// <summary>
    /// Gets or sets the unique identifier of the audit log entry.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Gets or sets the action performed (e.g., "ClientCreated", "SessionRevoked").
    /// </summary>
    public string Action { get; set; } = default!;

    /// <summary>
    /// Gets or sets the ID of the user or system actor who performed the action.
    /// </summary>
    public string? ActorUserId { get; set; }

    /// <summary>
    /// Gets or sets the type of the target entity (e.g., "Client", "Session").
    /// </summary>
    public string TargetType { get; set; } = default!;

    /// <summary>
    /// Gets or sets the ID of the target entity.
    /// </summary>
    public string TargetId { get; set; } = default!;

    /// <summary>
    /// Gets or sets when the action occurred.
    /// </summary>
    public DateTimeOffset Timestamp { get; set; }

    /// <summary>
    /// Gets or sets the IP address of the actor.
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// Gets or sets the user agent string of the actor.
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Gets or sets optional JSON or plain text metadata containing additional details.
    /// </summary>
    public string? Metadata { get; set; }
}
