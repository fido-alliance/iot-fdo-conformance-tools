<script lang="ts">
    import Login from './routes/Login.svelte'
    import NotFound from './routes/NotFound.svelte'
    import FdoDashboard from './routes/FdoDashboard.svelte';
    import {logout} from './lib/User.api'
    import Router, {location, push} from "svelte-spa-router"
    import Rv from './routes/RV.fdo.svelte';
    import Do from './routes/DO.fdo.svelte';
    import Device from './routes/Device.fdo.svelte';
    import Iop from './routes/IOP.svelte';

    let routes = {
        "/": Login,
        "/login": Login,
        "/test": FdoDashboard,
        "/test/rv": Rv,
        "/test/do": Do,
        "/test/device": Device,
        "/iop/": Iop,
        "*": NotFound,
    }

    let mode: string = "onprem"
    
    const handleLogout = async () => {
        await logout()
        push('/login')
    }
</script>


<div id="wrapper">

  <!-- Header -->
    <header id="header" class="alt">
      <!-- <h1>FDO Conformance Tools</h1> -->
    </header>

  <!-- Nav -->
    <nav id="nav">
      <ul>

        {#if $location.startsWith("/test/")}
            <li><a href="/#/test" class="button primary">Back to Dashboard</a></li>
        {/if}

        {#if $location === "/login" || $location === "/"}

        {:else if $location === "/register"}
            <li><a href="/#/login" class="button primary">Login</a></li>
        {:else}
            <li style="float: right;"><a href="#" on:click={handleLogout}>Logout</a></li>
        {/if}
      </ul>
    </nav>

  <!-- Main -->
    <div id="main">
      <Router {routes}></Router>
    </div>

  <!-- Footer -->
    <footer id="footer">
      <section>
        <ul class="icons">
          <li><a href="https://twitter.com/fidoalliance" class="icon brands fa-twitter alt"><span class="label">Twitter</span></a></li>
          <li><a href="https://github.com/fido-alliance" class="icon brands fa-github alt"><span class="label">GitHub</span></a></li>
        </ul>
        <p class="copyright" style="text-align: left;">&copy; 2022 - {(new Date()).getFullYear()} <a href="https://fidoalliance.org/">FIDO Alliance, Inc</a>. Designed by Yuriy Ackermann.</p>
      </section>
    </footer>
</div>

<style>
  .logo {
    height: 6em;
    padding: 1.5em;
    will-change: filter;
  }

  .logo.fido:hover {
    filter: drop-shadow(0 0 1em #fff564aa);
  }
  .read-the-docs {
    color: #888;
  }
</style> 