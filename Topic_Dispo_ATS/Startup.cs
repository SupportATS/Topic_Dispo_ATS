using Owin;



namespace Topic_Dispo_ATS

{

    public partial class Startup

    {

        public void Configuration(IAppBuilder app)

        {

            ConfigureAuth(app);

        }

    }

}