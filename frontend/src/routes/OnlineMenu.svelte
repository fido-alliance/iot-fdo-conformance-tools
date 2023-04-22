<script>
    import { push } from 'svelte-spa-router';
    import { ensureUserIsLoggedIn, getConfig } from '../lib/User.api'

    ensureUserIsLoggedIn()
    
    getConfig()
    .then(async (cfg) => {
        if (cfg.mode === "onprem") {
            push("/test")
        }
    })
</script>

<section id="first" class="main special">
    <header class="major">
        <h2>Choose your option</h2>
    </header>
    <ul class="features">
        <li>
            <span class="icon solid major style1 fa fa-microchip"></span>
            <h3>FDO Online Tools</h3>
            <p>Test online FDO device, rendezvous server, and device onboarding service.</p>
            <a href="/#/test" class="button">Open</a>

        </li>
        <li>
            <span class="icon solid major style3 fa fa-archive"></span>
            <h3>FIDO/FDO Tools Builds</h3>
            <p><b>FDO</b>, <b>FIDO2</b>, <b>UAF</b>, <b>U2F</b>. Binary builds of FIDO, and FDO test tools.</p>
            <a href="/#/builds" class="button">Open</a>
        </li>
    </ul>
</section>