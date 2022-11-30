using Cerbos.Sdk.Builders;
using Cerbos.Sdk;

internal class Program
{
    private static void Main(string[] args)
    {
        var client = new CerbosClientBuilder("http://localhost:3593").WithPlaintext().BuildBlockingClient();
        string[] actions = { "workspace:view", "pii:view" };

        CheckResourcesResult result = client
            .CheckResources(
                Principal.NewInstance("123", "USER")
                    .WithAttribute("workspaces", AttributeValue.MapValue(new Dictionary<string, AttributeValue>()
                    {
                        {
                            "workspaceA", AttributeValue.MapValue(new Dictionary<string, AttributeValue>()
                            {
                                {"role", AttributeValue.StringValue("OWNER")}
                            })
                        },
                        {
                            "workspaceB", AttributeValue.MapValue(new Dictionary<string, AttributeValue>()
                            {
                                {"role", AttributeValue.StringValue("MEMBER")}
                            })
                        }
                    })),

                ResourceAction.NewInstance("workspace", "workspaceA")
                    .WithActions(actions),

                ResourceAction.NewInstance("workspace", "workspaceB")
                    .WithActions(actions)
            );

        foreach (string n in new string[] { "workspaceA", "workspaceB" })
        {
            var r = result.Find(n);
            Console.Write(String.Format("\nResource: {0}\n", n));
            foreach (var i in r.GetAll())
            {
                String action = i.Key;
                Boolean isAllowed = i.Value;
                Console.Write(String.Format("\t{0} -> {1}\n", action, isAllowed ? "EFFECT_ALLOW" : "EFFECT_DENY"));
            }
        }
    }
}
