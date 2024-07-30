<script>
// @ts-nocheck

    import logo from './../assets/images/logo.jpeg';
    import { userStore } from './../store/store';
    import {
        Table, TableBody, TableBodyCell, TableBodyRow, TableHead, TableHeadCell,
        Drawer, CloseButton, Input, Navbar, NavBrand, NavHamburger, Button, Checkbox
    } from 'flowbite-svelte';
    import {
        InfoCircleSolid, ArrowRightOutline, SearchSolid,
        PlaySolid, StopSolid
    } from 'flowbite-svelte-icons';
    import { Greet, StartCapture, StopCapture } from "../../wailsjs/go/main/App.js";
    import { onMount, onDestroy } from 'svelte';
    import { writable } from 'svelte/store';
    import { sineIn } from 'svelte/easing';
    import { l2_protocols, appProtocols } from './../consts/protocols';

    const WS_URL = 'ws://localhost:4444/ws';
    const ac_transitionParamsBottom = { y: 320, duration: 200, easing: sineIn };

    const requests = writable([]);
    let scroll_to_bottom = true;
    let ac_hidden8 = true;
    let ac_current_packet = null;
    let capture_started = false;
    let export_file = $userStore.capture_export;
    let searchTerm = '';
    let active_row_color = "#063970";
    let active_row_idx;

    let ws;

    // Reactive statements
    $: filteredItems = $requests.filter(item =>
        JSON.stringify(item).toLowerCase().includes(searchTerm.toLowerCase())
    );
    $: capture_iface = $userStore.capture_iface;
    $: capture_promisc = $userStore.capture_promisc;

    // Lifecycle hooks
    onMount(() => connect());
    onDestroy(() => ws?.close());

    function connect() {
        ws = new WebSocket(WS_URL);

        ws.addEventListener('message', event => {
            const pcapData = JSON.parse(event.data);
            // console.log('Received message from server:', pcapData);
            requests.update(old => [...old, pcapData]);
            if (scroll_to_bottom) scrollToEnd();
        });

        ws.addEventListener('error', err => console.log('WebSocket error:', err));
        ws.addEventListener('close', () => console.log('WebSocket connection closed'));

        StartCapture(capture_iface, capture_promisc, '', export_file, false);
        capture_started = true;
    }

    async function toggleCapture() {
        if (capture_started) {
            console.log('Stopping capture');
            await StopCapture();
            ws.close();
            capture_started = false;
            console.log('Capture stopped');
        } else {
            console.log('Starting capture');
            requests.set([]);
            connect();
            capture_started = true;
            StartCapture(capture_iface, capture_promisc, '', export_file, false);
            console.log('Capture started');
        }
    }

    function scrollToEnd() {
    const container = document.getElementById('packets_div');
    if (container) {
      container.scrollTop = container.scrollHeight;
    }
  }
</script>

<main>
    <!-- Drawer -->
    <Drawer placement="bottom" width="w-full" transitionType="fly" transitionParams={ac_transitionParamsBottom} bind:hidden={ac_hidden8} id="sidebar8">
        <div class="flex items-center">
            <h5 id="drawer-label" class="inline-flex items-center mb-4 text-base font-semibold text-gray-500 dark:text-gray-400">
                <InfoCircleSolid class="w-5 h-5 me-2.5" /> Info
            </h5>
            <CloseButton on:click={() => (ac_hidden8 = true)} class="mb-4 dark:text-white" />
        </div>
        <p class="max-w-lg mb-6 text-sm text-gray-500 dark:text-gray-400">
            {ac_current_packet ? ac_current_packet.payload : 'No packet selected'}
        </p>
        <Button color="light" href="/">Learn more</Button>
        <Button href="/" class="px-4">Get access <ArrowRightOutline class="w-5 h-5 ms-2" /></Button>
    </Drawer>

    <!-- Navbar -->
    <Navbar>
        <NavBrand href="/">
            <img src={logo} class="me-3 h-6 sm:h-9" alt="Flowbite Logo" />
            <span class="self-center whitespace-nowrap text-xl font-semibold dark:text-white">GoShark</span>
        </NavBrand>
        <div class="flex md:order-2">
            <Checkbox class="mr-16" checked={scroll_to_bottom} on:click={()=> scroll_to_bottom = !scroll_to_bottom}>Scroll To End</Checkbox>
            <Button size="sm" color={capture_started ? 'red' : 'green'} on:click={toggleCapture}>
                {#if capture_started}
                    <StopSolid class="w-5 h-5 me-2" /> Stop Capturing
                {:else}
                    <PlaySolid class="w-5 h-5 me-2" /> Start Capturing
                {/if}
            </Button>

            <NavHamburger />
        </div>
    </Navbar>

    
    <!-- Packets Table -->
    <div class="packets_div" id="packets_div">
        <!-- Search and Packet Count -->
        <div class="flex flex-row justify-between mb-6">
            <div class="w-1/2">
                <Input type="text" placeholder="Enter a filter" bind:value={searchTerm}>
                    <SearchSolid slot="right" class="w-5 h-5 text-blue-500 dark:text-gray-400" />
                </Input>
            </div>
            <!-- <div class="w-96"> -->
                <p>Packets: {$requests.length}</p>
            <!-- </div> -->
        </div>
        <table>
            <thead>
                <tr>
                    <th>No.</th>
                    <th>Timestamp</th>
                    <th>Source</th>
                    <!-- <th>Source Addr</th> -->
                    <th>Destination</th>
                    <!-- <th>Destination Addr</th> -->
                    <th>Protocol</th>
                    <th>Length</th>
                    <!-- <th>Details</th> -->
                </tr>
            </thead>
            <tbody>
                {#each filteredItems as item, idx}
                    <tr style="background-color: {active_row_idx === idx ? active_row_color : item.color ? item.color : item.l2_protocol === "TCP" ? "#2596be" : "#e28743"};
                    color: {active_row_idx === idx ? "#ffffff" : "#000000"};
                    "
                    on:mouseenter={()=>{                        
                        active_row_idx = idx;
                    }}
                    on:mouseleave={()=>{                        
                        active_row_idx = null;
                    }}
                    on:click={()=>{
                        ac_current_packet = item;
                        ac_hidden8 = false;
                    }}
                    >
                        <td>{idx + 1}</td>
                        <td>{item.timestamp}</td>
                        <td>{item.source_host || item.source_ip_4 || item.source_mac}</td>
                        <!-- <td>{item.source_ip_4 || item.source_mac}</td> -->
                        <td>{item.destination_host || item.destination_ip_4 || item.destination_mac}</td>
                        <!-- <td>{item.destination_ip_4 || item.destination_mac}</td> -->
                        <td>
                            {item.protocol || item.l2_protocol}
                        </td>
                        <td>{item.length || 'N/A'}</td>
                        <!-- <td>
                            <Button color="dark" size="xs" on:click={() => {
                                ac_current_packet = item;
                                ac_hidden8 = false;
                            }}>
                                Details
                            </Button>
                        </td> -->
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
</main>

<style>

    .packets_div {
        margin: 1.5rem auto;
        width: 95%;
        max-height: 100vh;
        overflow-y: scroll;
        overflow-wrap: break-word;
        border: 1px solid #03104e;
        border-radius: 5px;
        padding: 10px;
    }
    table {
    width: 100%;
    border-collapse: collapse;
    font-family: Arial, sans-serif;
}

thead {
    background-color: #2c2c2c;
    color: #ffffff;
    position: sticky;
    top: -20px;
    z-index: 1; 
}

th {
    border: 1px solid #444;
    padding: 10px;
    text-align: left;
    font-size: 14px;
    font-weight: bold;
}

tbody tr:nth-child(even) {
    background-color: #f5f5f5;
}

tbody tr:nth-child(odd) {
    background-color: #ffffff;
}

td {
    border: 1px solid #ddd;
    padding: 8px;
    text-align: left;
    font-size: 12px;
    width: min-content;
    padding: 0px;
    padding-left: 5px;
    cursor: pointer;
}

/* td:hover {
    background-color: #90bc78;
} */

tbody tr:hover {
    background-color: #e0e0e0;
}

</style>
