using Microsoft.Data.Sqlite;
using SafeVault.Models;
namespace SafeVault.Data;
public sealed class UserRepository
{
    private readonly string _connectionString;
    public UserRepository(IConfiguration configuration)
    {
        var file = configuration["SAFEVAULT_DB"] ?? Path.Combine(AppContext.BaseDirectory, "safevault.db");
        _connectionString = new SqliteConnectionStringBuilder { DataSource = file, Mode = SqliteOpenMode.ReadWriteCreate }.ToString();
    }
    public UserRepository(string databaseFile) => _connectionString = new SqliteConnectionStringBuilder { DataSource = databaseFile }.ToString();
    private SqliteConnection Open() { var db = new SqliteConnection(_connectionString); db.Open(); return db; }
    public void Initialize()
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = """CREATE TABLE IF NOT EXISTS Users (Id INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT NOT NULL UNIQUE COLLATE NOCASE, Email TEXT NOT NULL UNIQUE COLLATE NOCASE, PasswordHash TEXT NOT NULL, Role TEXT NOT NULL CHECK(Role IN ('User','Admin')));""";
        cmd.ExecuteNonQuery();
    }
    public UserRecord? Find(string username)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT Id, Username, Email, PasswordHash, Role FROM Users WHERE Username = $username LIMIT 1";
        cmd.Parameters.AddWithValue("$username", username);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? new UserRecord(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4)) : null;
    }
    public UserRecord? FindById(long id)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT Id, Username, Email, PasswordHash, Role FROM Users WHERE Id = $id LIMIT 1";
        cmd.Parameters.AddWithValue("$id", id);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? new UserRecord(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4)) : null;
    }
    public bool Add(string username, string email, string passwordHash)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES ($username, $email, $hash, 'User')";
        cmd.Parameters.AddWithValue("$username", username);
        cmd.Parameters.AddWithValue("$email", email);
        cmd.Parameters.AddWithValue("$hash", passwordHash);
        try { return cmd.ExecuteNonQuery() == 1; }
        catch (SqliteException e) when (e.SqliteErrorCode == 19) { return false; }
    }
    // No public role assignment endpoint: admin privileges must be provisioned offline by an operator.
    public bool PromoteToAdmin(string username)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "UPDATE Users SET Role = 'Admin' WHERE Username = $username";
        cmd.Parameters.AddWithValue("$username", username);
        return cmd.ExecuteNonQuery() == 1;
    }
}
