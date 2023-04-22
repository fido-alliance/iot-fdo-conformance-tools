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
        <h2>FIDO Test Tools Builds</h2>
    </header>


    <div class="row gtr-uniform">
        <div class="col-12 col-12-xsmall">
            <iframe title="FIDO Test Tools Builds" src="/api/builds/" frameborder="0" style="min-width: 100%; min-height: 20rem"></iframe>
        </div>
    </div>
</section>