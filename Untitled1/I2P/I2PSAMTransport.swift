//
//  I2PSAMTransport.swift
//  Garlic transport for SAM sessions: LeaseSet resolution, the lease
//  registry the outbound tunnel's gateway dispatch consults, and the
//  OBEP/IBGW glue that joins garlic envelopes to the tunnel pipeline.
//

import Foundation
import CryptoKit

/// Maps lease tunnel IDs to their gateway routers. The outbound tunnel's
/// gateway-hop handler uses this to route a garlic envelope to the lease's
/// inbound gateway (lease-agnostic: one glue per tunnel serves all leases).
final class I2PGarlicLeaseRegistry {
    private let lock = NSLock()
    private var gatewaysByTunnelID: [UInt32: Data] = [:]

    func register(_ lease: I2PGarlicLease) {
        lock.lock()
        gatewaysByTunnelID[lease.tunnelID] = lease.gatewayRouterHash
        lock.unlock()
    }

    func gateway(forTunnelID tunnelID: UInt32) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return gatewaysByTunnelID[tunnelID]
    }
}

/// Sends garlic'd SAM frames through a session's outbound tunnel pool and
/// installs the tunnel-glue handlers on routers this router controls.
/// On the live network, remote hops run the standard IBGW/OBEP behavior and
/// no glue installation is required (see SAM_API.md, deviations).
final class I2PSAMGarlicTransport {
    let core: I2PSAMRouterCore
    let registry = I2PGarlicLeaseRegistry()
    private let lock = NSLock()
    private var gluedOutbound: Set<UInt32> = []
    private var gluedInbound: Set<UInt32> = []

    init(core: I2PSAMRouterCore) {
        self.core = core
    }

    // MARK: Resolution

    /// Resolves a destination hash to its freshest live lease, registering it
    /// so the outbound tunnel gateway can route garlic toward it.
    func resolveLease(_ destinationHash: Data) async throws -> I2PGarlicLease {
        guard let entry = await core.netDB.lookup(destinationHash), let leaseSet = entry.leaseSet else {
            throw I2PSAMError.destinationNotFound
        }
        let now = Date()
        guard let lease = leaseSet.leases.filter({ $0.expiration > now }).max(by: { $0.expiration < $1.expiration }) else {
            throw I2PSAMError.destinationNotFound
        }
        let garlicLease = I2PGarlicLease(gatewayRouterHash: lease.gatewayHash,
                                         tunnelID: lease.tunnelId,
                                         expiration: lease.expiration)
        registry.register(garlicLease)
        return garlicLease
    }

    // MARK: Send

    /// Wraps `message` in a garlic envelope addressed to `lease`, routes it
    /// through `pool`'s best outbound tunnel and delivers it to the first hop.
    func send(_ message: I2NPMessage, to lease: I2PGarlicLease,
              garlicSession: I2PGarlicSession, pool: I2PTunnelPool) async throws {
        let transmission = try I2PGarlicEndToEndPipeline.sendMessage(message, to: lease, session: garlicSession)
        guard let tunnel = pool.selectOutboundTunnel() else { throw I2PSAMError.noTunnels }
        installOutboundGlueIfNeeded(tunnel)
        let (payload, firstHop) = try I2PGarlicEndToEndPipeline.routeThroughTunnelPool(transmission, via: tunnel)
        let envelope = I2NPMessage(type: .tunnelData, payload: payload.serialize())
        try await core.delivery.deliver(envelope.serialize(), to: firstHop)
    }

    // MARK: Tunnel glue

    /// Outbound endpoint glue: the tunnel's gateway hop hands the inner
    /// (lease-addressed) TunnelGateway envelope to the lease's gateway router.
    func installOutboundGlueIfNeeded(_ tunnel: I2PTunnel) {
        let gatewayID = tunnel.gatewayTunnelID
        lock.lock()
        guard !gluedOutbound.contains(gatewayID) else {
            lock.unlock()
            return
        }
        gluedOutbound.insert(gatewayID)
        lock.unlock()
        guard let router = core.controlledRouter(tunnel.hops[0].routerHash) else { return }
        router.registerGateway(tunnelID: gatewayID) { [weak self] inner, _ in
            // `inner` is the lease-addressed TunnelGateway I2NP message.
            guard let self,
                  case .tunnelGateway(let leaseTunnelID, _) = try? inner.parseBody(),
                  let gatewayHash = self.registry.gateway(forTunnelID: leaseTunnelID) else { return }
            Task { try? await self.core.delivery.deliver(inner.serialize(), to: gatewayHash) }
        }
    }

    /// Inbound gateway glue: the lease gateway hop injects inbound garlic into
    /// this router's inbound tunnel (standard IBGW behavior on the live net).
    func installInboundGlueIfNeeded(_ tunnel: I2PTunnel) {
        let gatewayID = tunnel.gatewayTunnelID
        lock.lock()
        guard !gluedInbound.contains(gatewayID) else {
            lock.unlock()
            return
        }
        gluedInbound.insert(gatewayID)
        lock.unlock()
        guard let router = core.controlledRouter(tunnel.hops[0].routerHash) else { return }
        router.registerGateway(tunnelID: gatewayID) { [weak self] garlicMessage, _ in
            guard let self,
                  let payload = try? I2PTunnelDataProcessor.preprocess(garlicMessage.serialize(), via: tunnel) else { return }
            let envelope = I2NPMessage(type: .tunnelData, payload: payload.serialize())
            Task { try? await self.core.delivery.deliver(envelope.serialize(), to: tunnel.hops[0].routerHash) }
        }
    }
}