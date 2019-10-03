const getSelectedCandidates = async (peer) => {
  const candidates = await new Promise((resolve, reject) => {
    peer.getStats((err, candidates) => {
      if (err) {
        reject(err)
      }
      resolve(candidates)
    })
  })

  const findSelectedPair = (candidates) => {
    let candidate = candidates.find((c) => {
      // Spec-compliant
      if (c.type === 'transport' && c.selectedCandidatePairId) {
        // this c contains the ID of the selectedCandidate
        return true
      }

      // Old implementations
      if (
        (c.type === 'googCandidatePair' && c.googActiveConnection === 'true') ||
        ((c.type === 'candidatepair' || c.type === 'candidate-pair') && c.selected)
      ) {
        return true
      }
    })

    if (candidate.type === 'transport' && candidate.selectedCandidatePairId) {
      candidate = candidates.find((c) => candidate.selectedCandidatePairId === c.id)
    }

    return candidate
  }

  const selectedCandidatePair = findSelectedPair(candidates)

  // return if no selectedCandidatePair
  if (!selectedCandidatePair) {
    return
  }

  let localAddress
  let localPort
  let localType

  const local = candidates.find((c) => c.id === selectedCandidatePair.localCandidateId)

  if (local && (local.ip || local.address)) {
    // Spec
    localAddress = local.ip || local.address
    localPort = Number(local.port)
    localType = local.candidateType
  } else if (local && local.ipAddress) {
    // Firefox
    localAddress = local.ipAddress
    localPort = Number(local.portNumber)
    localType = local.candidateType
  } else if (typeof selectedCandidatePair.googLocalAddress === 'string') {
    // TODO: remove this once Chrome 58 is released
    const localAddressPort = selectedCandidatePair.googLocalAddress.split(':')
    localAddress = localAddressPort[0]
    localPort = Number(localAddressPort[1])
    localType = selectedCandidatePair.googLocalCandidateType // local, stun or relay
  }

  let remoteAddress
  let remotePort
  let remoteType

  const remote = candidates.find((c) => c.id === selectedCandidatePair.remoteCandidateId)

  if (remote && (remote.ip || remote.address)) {
    // Spec
    remoteAddress = remote.ip || remote.address
    remotePort = Number(remote.port)
    remoteType = remote.candidateType
  } else if (remote && remote.ipAddress) {
    // Firefox
    remoteAddress = remote.ipAddress
    remotePort = Number(remote.portNumber)
    remoteType = remote.candidateType
  } else if (typeof selectedCandidatePair.googRemoteAddress === 'string') {
    // TODO: remove this once Chrome 58 is released
    const remoteAddressPort = selectedCandidatePair.googRemoteAddress.split(':')
    remoteAddress = remoteAddressPort[0]
    remotePort = Number(remoteAddressPort[1])
    remoteType = selectedCandidatePair.googRemoteCandidateType // local, stun or relay
  }

  return {
    localAddress,
    localPort,
    localType,
    remoteAddress,
    remotePort,
    remoteType
  }
}

export {
  getSelectedCandidates
}
