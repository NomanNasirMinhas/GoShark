<script>
    import logo from "./../assets/images/logo.jpeg";
    import { userStore } from "./../store/store";
    import { Table, TableBody, TableBodyCell, TableBodyRow, TableHead, TableHeadCell, TableSearch } from 'flowbite-svelte';
    import { Drawer, CloseButton, A } from 'flowbite-svelte';
    import { InfoCircleSolid, ArrowRightOutline } from 'flowbite-svelte-icons';
    import { Input, ButtonGroup } from 'flowbite-svelte';
    import { SearchSolid } from 'flowbite-svelte-icons';
    import { sineIn } from 'svelte/easing';
    import { Navbar, NavBrand, NavLi, NavUl, NavHamburger } from "flowbite-svelte";
    import { PlaySolid, StopSolid } from "flowbite-svelte-icons";
    import { Button } from "flowbite-svelte";
    import { Label, Select } from "flowbite-svelte";
    import { Greet, IsRoot, StartCapture, GetAllDevices, StopCapture } from "../../wailsjs/go/main/App.js";
    import { onMount } from "svelte";
    import { writable, get } from "svelte/store";
  
    // Writable store for packet data
    const requests = writable([]);
  
    let ac_hidden8 = true;
    let ac_transitionParamsBottom = { y: 320, duration: 200, easing: sineIn };
    let ac_current_packet;
    let isAdmin;
    let capture_started = false;
    let searchTerm = '';

    let ws;
  
    // Filtered items based on search term
    let filteredItems = [];
    $: {
      filteredItems = $requests.filter(item =>
        JSON.stringify(item).toLowerCase().includes(searchTerm.toLowerCase())
      );
    }
  
    let capture_iface = $userStore.capture_iface;
    let capture_promisc = $userStore.capture_promisc;
  
    // Initialize WebSocket connection
    onMount(() => {
      connect();
    });

    function connect(){
        ws = new WebSocket("ws://localhost:4444/ws");
  
      ws.addEventListener("message", (message) => {
        let pcapData = JSON.parse(message.data);
        console.log("Received message from server: ", pcapData);
        requests.update(old => [...old, pcapData]);
      });
  
      ws.addEventListener("error", (err) => {
        console.log("WebSocket error:", err);
      });
  
      ws.addEventListener("close", () => {
        console.log("WebSocket connection closed");
      });
  
      StartCapture(capture_iface, capture_promisc, "");
      capture_started = true;
  
      return () => {
        ws.close();
        StopCapture();
        capture_started = false;
      };
    }
  
    // Function to start or stop packet capture
    const toggleCapture = async () => {
      if (capture_started) {
        console.log("Stopping capture");
        await StopCapture();
        ws.close();
        capture_started = false;
        console.log("Capture stopped");
      } else {
        console.log("Starting capture");
        requests.set([]);
        connect();
        capture_started = true;
        StartCapture(capture_iface, capture_promisc, "");
        console.log("Capture started");
      }
    };
  </script>
  
  <main>
    <Drawer placement="bottom" width="w-full" transitionType="fly" transitionParams={ac_transitionParamsBottom} bind:hidden={ac_hidden8} id="sidebar8">
      <div class="flex items-center">
        <h5 id="drawer-label" class="inline-flex items-center mb-4 text-base font-semibold text-gray-500 dark:text-gray-400">
          <InfoCircleSolid class="w-5 h-5 me-2.5" />Info
        </h5>
        <CloseButton on:click={() => (ac_hidden8 = true)} class="mb-4 dark:text-white" />
      </div>
      <p class="max-w-lg mb-6 text-sm text-gray-500 dark:text-gray-400">
        {ac_current_packet ? ac_current_packet["full_packet_data"] : "No packet selected"}
      </p>
      <Button color="light" href="/">Learn more</Button>
      <Button href="/" class="px-4">Get access <ArrowRightOutline class="w-5 h-5 ms-2" /></Button>
    </Drawer>
  
    <Navbar>
      <NavBrand href="/">
        <img src={logo} class="me-3 h-6 sm:h-9" alt="Flowbite Logo" />
        <span class="self-center whitespace-nowrap text-xl font-semibold dark:text-white">GoShark</span>
      </NavBrand>
      <div class="flex md:order-2">
        <Button size="sm" color={capture_started ? "red" : "green"} on:click={toggleCapture}>
          {#if capture_started}
            <StopSolid class="w-5 h-5 me-2" /> Stop Capturing
          {:else}
            <PlaySolid class="w-5 h-5 me-2" /> Start Capturing
          {/if}
        </Button>
        <NavHamburger />
      </div>
    </Navbar>
  
    <div class="flex flex-row justify-items-start">
      <div class="mb-6 mt-16 w-96 ml-16">
        <Input type="text" placeholder="Enter a filter" bind:value={searchTerm}>
          <SearchSolid slot="right" class="w-5 h-5 text-blue-500 dark:text-gray-400" />
        </Input>
      </div>
  
      <div class="mb-6 mt-16 w-96 ml-16">
        <h3>Total Captured Packets: {$requests.length}</h3>
      </div>
    </div>
  
    <div class="packets_div">
      <Table>
        <TableHead>
          <TableHeadCell>Timestamp</TableHeadCell>
          <TableHeadCell>Source IP</TableHeadCell>
          <TableHeadCell>Source Port</TableHeadCell>
          <TableHeadCell>Destination IP</TableHeadCell>
          <TableHeadCell>Destination Port</TableHeadCell>
          <TableHeadCell>Details</TableHeadCell>
        </TableHead>
        <TableBody tableBodyClass="divide-y">
          {#each filteredItems as item}
            <TableBodyRow style="height: 30px; padding: 0%;">
              <TableBodyCell>{item.timestamp}</TableBodyCell>
              <TableBodyCell>{item.ip?.SrcIP || 'N/A'}</TableBodyCell>
              <TableBodyCell>{item.tcp?.SrcPort || 'N/A'}</TableBodyCell>
              <TableBodyCell>{item.ip?.DstIP || 'N/A'}</TableBodyCell>
              <TableBodyCell>{item.tcp?.DstPort || 'N/A'}</TableBodyCell>
              <TableBodyCell>
                <Button color="dark" size='xs' on:click={() => {
                  ac_current_packet = item;
                  ac_hidden8 = false;
                }}>
                  Details
                </Button>
              </TableBodyCell>
            </TableBodyRow>
          {/each}
        </TableBody>
      </Table>
    </div>
  </main>
  
  <style>
    .packets_div {
      margin: 1.5rem auto;
      width: 95%;
      max-height: 900px;
      overflow-y: scroll;
      overflow-wrap: break-word;
      border: 1px solid #03104e;
      border-radius: 5px;
      padding: 10px;
    }
  </style>
  