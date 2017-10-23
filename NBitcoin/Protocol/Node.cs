#if !NOSOCKET

using NBitcoin.Protocol.Behaviors;
using NBitcoin.Protocol.Filters;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

namespace NBitcoin.Protocol
{
	public delegate void NodeEventHandler(Node node);
	public delegate void NodeEventMessageIncoming(Node node, IncomingMessage message);
	public delegate void NodeStateEventHandler(Node node, NodeState oldState);

	public class Node : IDisposable
	{
		#region Properties

		/// <summary>
		/// Send addr unsollicited message of the AddressFrom peer when passing to Handshaked state
		/// </summary>
		private bool advertize;

		/// <summary>
		/// Transaction options we prefer and which is also supported by peer
		/// </summary>
		private TransactionOptions actualTransactionOptions
		{
			get { return PreferredTransactionOptions & SupportedTransactionOptions; }
		}

		private readonly NodeBehaviorsCollection behaviors;
		public NodeBehaviorsCollection Behaviors
		{
			get { return behaviors; }
		}

		internal readonly NodeConnection Connection;

		private PerformanceCounter counter;
		public PerformanceCounter Counter
		{
			get
			{
				if (counter == null)
					counter = new PerformanceCounter();
				return counter;
			}
		}

		internal event NodeEventHandler Disconnected;
		public NodeDisconnectReason DisconnectReason;
		private int disconnecting;
		public event NodeEventMessageIncoming MessageReceived;
		public event NodeStateEventHandler StateChanged;

		private readonly NodeFiltersCollection _Filters = new NodeFiltersCollection();
		public NodeFiltersCollection Filters
		{
			get
			{
				return _Filters;
			}
		}

		public bool Inbound { get; private set; }

		public bool IsConnected
		{
			get
			{
				return State == NodeState.Connected || State == NodeState.HandShaked;
			}
		}

		internal DateTimeOffset LastSeen;

		private readonly NetworkAddress peer;
		public NetworkAddress Peer
		{
			get { return peer; }
		}

		private readonly MessageProducer<IncomingMessage> messageProducer = new MessageProducer<IncomingMessage>();
		public MessageProducer<IncomingMessage> MessageProducer
		{
			get { return messageProducer; }
		}

		private readonly VersionPayload myVersion;
		public VersionPayload MyVersion
		{
			get { return myVersion; }
		}

		public Network Network { get; set; }

		private VersionPayload peerVersion;
		public VersionPayload PeerVersion
		{
			get { return peerVersion; }
		}

		internal TimeSpan PollHeaderDelay = TimeSpan.FromMinutes(1.0);

		IPAddress remoteSocketAddress;
		public IPAddress RemoteSocketAddress
		{
			get { return remoteSocketAddress; }
		}

		IPEndPoint remoteSocketEndpoint;
		public IPEndPoint RemoteSocketEndpoint
		{
			get { return remoteSocketEndpoint; }
		}

		int remoteSocketPort;
		public int RemoteSocketPort
		{
			get { return remoteSocketPort; }
		}

		internal bool ReuseBuffer;

		volatile NodeState state = NodeState.Offline;
		public NodeState State
		{
			get { return state; }

			set
			{
				TraceCorrelation.LogInside(() => NodeServerTrace.Information("State changed from " + state + " to " + value));
				var previous = state;
				state = value;
				if (previous != state)
				{
					OnStateChanged(previous);
					if (value == NodeState.Failed || value == NodeState.Offline)
					{
						// NETSTDCONV 
						// TraceCorrelation.LogInside(() => NodeServerTrace.Trace.TraceEvent(TraceEventType.Stop, 0, "Communication closed"));
						TraceCorrelation.LogInside(() => NodeServerTrace.Trace.TraceEvent(TraceEventType.Critical, 0, "Communication closed"));
						OnDisconnected();
					}
				}
			}
		}

		public TimeSpan? TimeOffset { get; private set; }

		private TransactionOptions preferredTransactionOptions = TransactionOptions.All;
		/// <summary>Transaction options we would like.</summary>
		public TransactionOptions PreferredTransactionOptions
		{
			get { return preferredTransactionOptions; }
		}

		TransactionOptions supportedTransactionOptions = TransactionOptions.None;
		/// <summary>
		/// Transaction options supported by the peer
		/// </summary>
		public TransactionOptions SupportedTransactionOptions
		{
			get { return supportedTransactionOptions; }
		}

		/// <summary>
		/// The negociated protocol version (minimum of supported version between MyVersion and the PeerVersion)
		/// </summary>
		internal ProtocolVersion Version
		{
			get
			{
				var peerVersion = PeerVersion == null ? MyVersion.Version : PeerVersion.Version;
				var myVersion = MyVersion.Version;
				var min = Math.Min((uint)peerVersion, (uint)myVersion);
				return (ProtocolVersion)min;
			}
		}

		#endregion

		private void OnStateChanged(NodeState previous)
		{
			var stateChanged = StateChanged;
			if (stateChanged != null)
			{
				foreach (var handler in stateChanged.GetInvocationList().Cast<NodeStateEventHandler>())
				{
					try
					{
						handler.DynamicInvoke(this, previous);
					}
					catch (TargetInvocationException ex)
					{
						TraceCorrelation.LogInside(() => NodeServerTrace.Error("Error while StateChanged event raised", ex.InnerException));
					}
				}
			}
		}

		internal void OnMessageReceived(IncomingMessage message)
		{
			var version = message.Message.Payload as VersionPayload;
			if (version != null && State == NodeState.HandShaked)
			{
				if (message.Node.Version >= ProtocolVersion.REJECT_VERSION)
					message.Node.SendMessageAsync(new RejectPayload()
					{
						Code = RejectCode.DUPLICATE
					});
			}

			if (version != null)
			{
				TimeOffset = DateTimeOffset.Now - version.Timestamp;
				if ((version.Services & NodeServices.NODE_WITNESS) != 0)
					supportedTransactionOptions |= TransactionOptions.Witness;
			}

			var havewitness = message.Message.Payload as HaveWitnessPayload;
			if (havewitness != null)
				supportedTransactionOptions |= TransactionOptions.Witness;

			var last = new ActionFilter((m, n) =>
			{
				MessageProducer.PushMessage(m);
				var messageReceived = MessageReceived;
				if (messageReceived != null)
				{
					foreach (var handler in messageReceived.GetInvocationList().Cast<NodeEventMessageIncoming>())
					{
						try
						{
							handler.DynamicInvoke(this, m);
						}
						catch (TargetInvocationException ex)
						{
							TraceCorrelation.LogInside(() => NodeServerTrace.Error("Error while OnMessageReceived event raised", ex.InnerException), false);
						}
					}
				}
			});

			var enumerator = Filters.Concat(new[] { last }).GetEnumerator();
			FireFilters(enumerator, message);
		}

		private void OnSendingMessage(Payload payload, Action final)
		{
			var enumerator = Filters.Concat(new[] { new ActionFilter(null, (n, p, a) => final()) }).GetEnumerator();
			FireFilters(enumerator, payload);
		}

		private void FireFilters(IEnumerator<INodeFilter> enumerator, Payload payload)
		{
			if (enumerator.MoveNext())
			{
				var filter = enumerator.Current;
				try
				{
					filter.OnSendingMessage(this, payload, () => FireFilters(enumerator, payload));
				}
				catch (Exception ex)
				{
					TraceCorrelation.LogInside(() => NodeServerTrace.Error("Unhandled exception raised by a node filter (OnSendingMessage)", ex.InnerException), false);
				}
			}
		}

		private void FireFilters(IEnumerator<INodeFilter> enumerator, IncomingMessage message)
		{
			if (enumerator.MoveNext())
			{
				var filter = enumerator.Current;
				try
				{
					filter.OnReceivingMessage(message, () => FireFilters(enumerator, message));
				}
				catch (Exception ex)
				{
					TraceCorrelation.LogInside(() => NodeServerTrace.Error("Unhandled exception raised by a node filter (OnReceivingMessage)", ex.InnerException), false);
				}
			}
		}

		private void OnDisconnected()
		{
			var disconnected = Disconnected;
			if (disconnected != null)
			{
				foreach (var handler in disconnected.GetInvocationList().Cast<NodeEventHandler>())
				{
					try
					{
						handler.DynamicInvoke(this);
					}
					catch (TargetInvocationException ex)
					{
						TraceCorrelation.LogInside(() => NodeServerTrace.Error("Error while Disconnected event raised", ex.InnerException));
					}
				}
			}
		}

		/// <summary>
		/// Connect to a random node on the network
		/// </summary>
		/// <param name="network">The network to connect to</param>
		/// <param name="parameters">The parameters used by the found node, use AddressManagerBehavior.GetAddrman for finding peers</param>
		/// <param name="connectedEndpoints">The already connected endpoints, the new endpoint will be select outside of existing groups</param>
		/// <param name="getGroup">Group selector, by default NBicoin.IpExtensions.GetGroup</param>
		/// <returns></returns>
		public static Node Connect(Network network, NodeConnectionParameters parameters = null, IPEndPoint[] connectedEndpoints = null, Func<IPEndPoint, byte[]> getGroup = null)
		{
			return Connect(network, parameters, new Func<IPEndPoint[]>(() => connectedEndpoints), getGroup);
		}

		/// <summary>
		/// Connect to a random node on the network
		/// </summary>
		/// <param name="network">The network to connect to</param>
		/// <param name="parameters">The parameters used by the found node, use AddressManagerBehavior.GetAddrman for finding peers</param>
		/// <param name="connectedEndpoints">Function returning the already connected endpoints, the new endpoint will be select outside of existing groups</param>
		/// <param name="getGroup">Group selector, by default NBicoin.IpExtensions.GetGroup</param>
		/// <returns></returns>
		public static Node Connect(Network network, NodeConnectionParameters parameters, Func<IPEndPoint[]> connectedEndpoints, Func<IPEndPoint, byte[]> getGroup = null)
		{
			getGroup = getGroup ?? new Func<IPEndPoint, byte[]>((a) => IpExtensions.GetGroup(a.Address));

			var result = connectedEndpoints();
			if (result == null)
				connectedEndpoints = new Func<IPEndPoint[]>(() => new IPEndPoint[0]);

			parameters = parameters ?? new NodeConnectionParameters();

			var addrmanBehavior = parameters.TemplateBehaviors.FindOrCreate(() => new AddressManagerBehavior(new AddressManager()));
			var addrman = AddressManagerBehavior.GetAddrman(parameters);

			DateTimeOffset start = DateTimeOffset.UtcNow;

			while (true)
			{
				parameters.ConnectCancellation.ThrowIfCancellationRequested();

				if (addrman.Count == 0 || DateTimeOffset.UtcNow - start > TimeSpan.FromSeconds(60))
				{
					addrmanBehavior.DiscoverPeers(network, parameters);
					start = DateTimeOffset.UtcNow;
				}

				NetworkAddress addr = null;
				int groupFail = 0;

				while (true)
				{
					if (groupFail > 50)
					{
						parameters.ConnectCancellation.WaitHandle.WaitOne((int)TimeSpan.FromSeconds(60).TotalMilliseconds);
						break;
					}

					addr = addrman.Select();
					if (addr == null)
					{
						parameters.ConnectCancellation.WaitHandle.WaitOne(1000);
						break;
					}

					if (!addr.Endpoint.Address.IsValid())
						continue;

					var endPoint = getGroup(addr.Endpoint);
					var groupExist = connectedEndpoints().Any(a => getGroup(a).SequenceEqual(endPoint));
					if (groupExist)
					{
						groupFail++;
						continue;
					}

					break;
				}

				if (addr == null)
					continue;
				try
				{
					var timeout = new CancellationTokenSource(5000);
					var param2 = parameters.Clone();
					param2.ConnectCancellation = CancellationTokenSource.CreateLinkedTokenSource(parameters.ConnectCancellation, timeout.Token).Token;
					var node = Connect(network, addr.Endpoint, param2);
					return node;
				}
				catch (OperationCanceledException ex)
				{
					if (ex.CancellationToken == parameters.ConnectCancellation)
						throw;
				}
				catch (SocketException)
				{
					parameters.ConnectCancellation.WaitHandle.WaitOne(500);
				}
			}
		}

		/// <summary>
		/// Connect to the node of this machine
		/// </summary>
		/// <param name="network"></param>
		/// <param name="parameters"></param>
		/// <returns></returns>
		public static Node ConnectToLocal(Network network, NodeConnectionParameters parameters)
		{
			return Connect(network, Utils.ParseIpEndpoint("localhost", network.DefaultPort), parameters);
		}

		public static Node ConnectToLocal(Network network, ProtocolVersion myVersion = ProtocolVersion.PROTOCOL_VERSION, bool isRelay = true, CancellationToken cancellation = default(CancellationToken))
		{
			return ConnectToLocal(network, new NodeConnectionParameters()
			{
				ConnectCancellation = cancellation,
				IsRelay = isRelay,
				Version = myVersion
			});
		}

		public static Node Connect(Network network, string endpoint, NodeConnectionParameters parameters)
		{
			return Connect(network, Utils.ParseIpEndpoint(endpoint, network.DefaultPort), parameters);
		}

		public static Node Connect(Network network, string endpoint, ProtocolVersion myVersion = ProtocolVersion.PROTOCOL_VERSION, bool isRelay = true, CancellationToken cancellation = default(CancellationToken))
		{
			return Connect(network, Utils.ParseIpEndpoint(endpoint, network.DefaultPort), myVersion, isRelay, cancellation);
		}

		public static Node Connect(Network network, IPEndPoint endpoint, NodeConnectionParameters parameters)
		{
			var peer = new NetworkAddress()
			{
				Time = DateTimeOffset.UtcNow,
				Endpoint = endpoint
			};

			return new Node(peer, network, parameters);
		}

		public static Node Connect(Network network, IPEndPoint endpoint, ProtocolVersion myVersion = ProtocolVersion.PROTOCOL_VERSION, bool isRelay = true, CancellationToken cancellation = default(CancellationToken))
		{
			return Connect(network, endpoint, new NodeConnectionParameters()
			{
				ConnectCancellation = cancellation,
				IsRelay = isRelay,
				Version = myVersion,
				Services = NodeServices.Nothing,
			});
		}

		private Node(NetworkAddress peer, Network network, NodeConnectionParameters parameters)
		{
			parameters = parameters ?? new NodeConnectionParameters();

			var addressManager = AddressManagerBehavior.GetAddrman(parameters);

			Inbound = false;
			behaviors = new NodeBehaviorsCollection(this);
			myVersion = parameters.CreateVersion(peer.Endpoint, network);
			Network = network;
			this.peer = peer;
			LastSeen = peer.Time;

			var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
			socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);

			Connection = new NodeConnection(this, socket);
			socket.ReceiveBufferSize = parameters.ReceiveBufferSize;
			socket.SendBufferSize = parameters.SendBufferSize;

			using (TraceCorrelation.Open())
			{
				try
				{
					using (var completedEvent = new ManualResetEvent(false))
					{
						using (var socketEventManager = NodeSocketEventManager.Create(completedEvent, peer.Endpoint))
						{
							//If the socket connected straight away (synchronously) unblock all threads.
							if (!socket.ConnectAsync(socketEventManager.Instance))
								completedEvent.Set();

							//Otherwise wait for the socket connection to complete OR if the operation got cancelled.
							WaitHandle.WaitAny(new WaitHandle[] { completedEvent, parameters.ConnectCancellation.WaitHandle });

							parameters.ConnectCancellation.ThrowIfCancellationRequested();

							if (socketEventManager.Instance.SocketError != SocketError.Success)
								throw new SocketException((int)socketEventManager.Instance.SocketError);

							var remoteEndpoint = (IPEndPoint)(socket.RemoteEndPoint ?? socketEventManager.Instance.RemoteEndPoint);
							remoteSocketAddress = remoteEndpoint.Address;
							remoteSocketEndpoint = remoteEndpoint;
							remoteSocketPort = remoteEndpoint.Port;

							State = NodeState.Connected;

							NodeServerTrace.Information("Outbound connection successful.");

							if (addressManager != null)
								addressManager.Attempt(Peer);
						}
					}
				}
				catch (OperationCanceledException)
				{
					Utils.SafeCloseSocket(socket);

					NodeServerTrace.Information("Connection to node cancelled");

					State = NodeState.Offline;

					if (addressManager != null)
						addressManager.Attempt(Peer);

					throw;
				}
				catch (Exception ex)
				{
					Utils.SafeCloseSocket(socket);
					NodeServerTrace.Error("Error connecting to the remote endpoint ", ex);

					DisconnectReason = new NodeDisconnectReason()
					{
						Reason = "Unexpected exception while connecting to socket",
						Exception = ex
					};

					State = NodeState.Failed;

					if (addressManager != null)
						addressManager.Attempt(Peer);

					throw;
				}

				InitDefaultBehaviors(parameters);

				Connection.BeginListen();
			}
		}

		internal Node(NetworkAddress peer, Network network, NodeConnectionParameters parameters, Socket socket, VersionPayload peerVersion)
		{
			remoteSocketAddress = ((IPEndPoint)socket.RemoteEndPoint).Address;
			remoteSocketEndpoint = ((IPEndPoint)socket.RemoteEndPoint);
			remoteSocketPort = ((IPEndPoint)socket.RemoteEndPoint).Port;

			Inbound = true;
			behaviors = new NodeBehaviorsCollection(this);
			myVersion = parameters.CreateVersion(peer.Endpoint, network);
			Network = network;
			this.peer = peer;
			Connection = new NodeConnection(this, socket);
			this.peerVersion = peerVersion;
			LastSeen = peer.Time;

			TraceCorrelation.LogInside(() =>
			{
				NodeServerTrace.Information("Connected to advertised node " + this.peer.Endpoint);
				State = NodeState.Connected;
			});

			InitDefaultBehaviors(parameters);

			Connection.BeginListen();
		}

		private void InitDefaultBehaviors(NodeConnectionParameters parameters)
		{
			advertize = parameters.Advertize;
			preferredTransactionOptions = parameters.PreferredTransactionOptions;
			ReuseBuffer = parameters.ReuseBuffer;

			behaviors.DelayAttach = true;
			foreach (var behavior in parameters.TemplateBehaviors)
			{
				behaviors.Add(behavior.Clone());
			}

			behaviors.DelayAttach = false;
		}

		TraceCorrelation traceCorrelation = null;
		[DebuggerBrowsable(DebuggerBrowsableState.Never)]
#if NOTRACESOURCE
		internal
#else
		public
#endif
 TraceCorrelation TraceCorrelation
		{
			get
			{
				if (traceCorrelation == null)
					traceCorrelation = new TraceCorrelation(NodeServerTrace.Trace, "Communication with " + Peer.Endpoint.ToString());
				return traceCorrelation;
			}
		}

		/// <summary>
		/// Send a message to the peer asynchronously
		/// </summary>
		/// <param name="payload">The payload to send</param>
		/// <param name="System.OperationCanceledException">The node has been disconnected</param>
		public Task SendMessageAsync(Payload payload)
		{
			if (payload == null)
				throw new ArgumentNullException("payload");

			TaskCompletionSource<bool> completion = new TaskCompletionSource<bool>();

			if (!IsConnected)
			{
				completion.SetException(new OperationCanceledException("The peer has been disconnected"));
				return completion.Task;
			}

			// NETSTDCONV
			// var activity = Trace.CorrelationManager.ActivityId;
			var activity = Guid.NewGuid();

			Action final = () =>
			{
				Connection.Messages.Add(new SentMessage()
				{
					Payload = payload,
					ActivityId = activity,
					Completion = completion
				});
			};

			OnSendingMessage(payload, final);

			return completion.Task;
		}

		/// <summary>
		/// Send a message to the peer synchronously
		/// </summary>
		/// <param name="payload">The payload to send</param>
		/// <exception cref="System.ArgumentNullException">Payload is null</exception>
		/// <param name="System.OperationCanceledException">The node has been disconnected, or the cancellation token has been set to canceled</param>
		public void SendMessage(Payload payload, CancellationToken cancellation = default(CancellationToken))
		{
			try
			{
				SendMessageAsync(payload).Wait(cancellation);
			}
			catch (AggregateException aex)
			{
				ExceptionDispatchInfo.Capture(aex.InnerException).Throw();
				throw;
			}
		}

		public TPayload ReceiveMessage<TPayload>(TimeSpan timeout) where TPayload : Payload
		{
			var source = new CancellationTokenSource();
			source.CancelAfter(timeout);
			return ReceiveMessage<TPayload>(source.Token);
		}

		public TPayload ReceiveMessage<TPayload>(CancellationToken cancellationToken = default(CancellationToken)) where TPayload : Payload
		{
			using (var listener = new NodeListener(this))
			{
				return listener.ReceivePayload<TPayload>(cancellationToken);
			}
		}

		public void VersionHandshake(CancellationToken cancellationToken = default(CancellationToken))
		{
			VersionHandshake(null, cancellationToken);
		}

		internal void VersionHandshake(NodeRequirement requirements, CancellationToken cancellationToken = default(CancellationToken))
		{
			requirements = requirements ?? new NodeRequirement();

			using (var listener = CreateListener()
									.Where(p => p.Message.Payload is VersionPayload ||
												p.Message.Payload is RejectPayload ||
												p.Message.Payload is VerAckPayload))
			{

				SendMessageAsync(MyVersion);

				var payload = listener.ReceivePayload<Payload>(cancellationToken);
				if (payload is RejectPayload)
				{
					throw new ProtocolException("Handshake rejected : " + ((RejectPayload)payload).Reason);
				}

				var version = (VersionPayload)payload;
				peerVersion = version;
				if (!version.AddressReceiver.Address.Equals(MyVersion.AddressFrom.Address))
				{
					NodeServerTrace.Warning("Different external address detected by the node " + version.AddressReceiver.Address + " instead of " + MyVersion.AddressFrom.Address);
				}

				if (version.Version < ProtocolVersion.MIN_PEER_PROTO_VERSION)
				{
					NodeServerTrace.Warning("Outdated version " + version.Version + " disconnecting");
					Disconnect("Outdated version");
					return;
				}

				if (!requirements.Check(version))
				{
					Disconnect("The peer does not support the required services requirement");
					return;
				}

				SendMessageAsync(new VerAckPayload());
				listener.ReceivePayload<VerAckPayload>(cancellationToken);
				State = NodeState.HandShaked;

				if (advertize && MyVersion.AddressFrom.Address.IsRoutable(true))
				{
					SendMessageAsync(new AddrPayload(new NetworkAddress(MyVersion.AddressFrom)
					{
						Time = DateTimeOffset.UtcNow
					}));
				}
			}
		}

		public void RespondToHandShake(CancellationToken cancellation = default(CancellationToken))
		{
			using (TraceCorrelation.Open())
			{
				using (var list = CreateListener().Where(m => m.Message.Payload is VerAckPayload || m.Message.Payload is RejectPayload))
				{
					NodeServerTrace.Information("Responding to handshake");
					SendMessageAsync(MyVersion);
					var message = list.ReceiveMessage(cancellation);
					var reject = message.Message.Payload as RejectPayload;
					if (reject != null)
						throw new ProtocolException("Version rejected " + reject.Code + " : " + reject.Reason);
					SendMessageAsync(new VerAckPayload());
					State = NodeState.HandShaked;
				}
			}
		}

		public void Disconnect()
		{
			Disconnect(null, null);
		}

		public void Disconnect(string reason, Exception exception = null)
		{
			DisconnectAsync(reason, exception);
			AssertNoListeningThread();
			Connection.Disconnected.WaitOne();
		}

		private void AssertNoListeningThread()
		{
			if (Connection._ListenerThreadId == Thread.CurrentThread.ManagedThreadId)
				throw new InvalidOperationException("Using Disconnect on this thread would result in a deadlock, use DisconnectAsync instead");
		}

		public void DisconnectAsync()
		{
			DisconnectAsync(null, null);
		}

		public void DisconnectAsync(string reason, Exception exception = null)
		{
			if (!IsConnected)
				return;

			if (Interlocked.CompareExchange(ref disconnecting, 1, 0) == 1)
				return;

			using (TraceCorrelation.Open())
			{
				NodeServerTrace.Information("Disconnection request " + reason);
				State = NodeState.Disconnecting;
				Connection.Cancel.Cancel();
				if (DisconnectReason == null)
					DisconnectReason = new NodeDisconnectReason()
					{
						Reason = reason,
						Exception = exception
					};
			}
		}

		/// <summary>
		/// Get the chain of headers from the peer (thread safe)
		/// </summary>
		/// <param name="hashStop">The highest block wanted</param>
		/// <param name="cancellationToken"></param>
		/// <returns>The chain of headers</returns>
		public ConcurrentChain GetChain(uint256 hashStop = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			ConcurrentChain chain = new ConcurrentChain(Network);
			SynchronizeChain(chain, hashStop, cancellationToken);
			return chain;
		}

		public IEnumerable<ChainedBlock> GetHeadersFromFork(ChainedBlock currentTip, uint256 hashStop = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			AssertState(NodeState.HandShaked, cancellationToken);

			NodeServerTrace.Information("Building chain");

			using (var listener = this.CreateListener().OfType<HeadersPayload>())
			{
				int acceptMaxReorgDepth = 0;

				while (true)
				{
					//Get before last so, at the end, we should only receive 1 header equals to this one (so we will not have race problems with concurrent GetChains)
					var awaited = currentTip.Previous == null ? currentTip.GetLocator() : currentTip.Previous.GetLocator();
					SendMessageAsync(new GetHeadersPayload()
					{
						BlockLocators = awaited,
						HashStop = hashStop
					});

					while (true)
					{
						bool isOurs = false;
						HeadersPayload headers = null;

						using (var headersCancel = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
						{
							headersCancel.CancelAfter(PollHeaderDelay);
							try
							{
								headers = listener.ReceivePayload<HeadersPayload>(headersCancel.Token);
							}
							catch (OperationCanceledException)
							{
								acceptMaxReorgDepth += 6;
								if (cancellationToken.IsCancellationRequested)
									throw;
								break; //Send a new GetHeaders
							}
						}
						if (headers.Headers.Count == 0 && PeerVersion.StartHeight == 0 && currentTip.HashBlock == Network.GenesisHash) //In the special case where the remote node is at height 0 as well as us, then the headers count will be 0
							yield break;
						if (headers.Headers.Count == 1 && headers.Headers[0].GetHash() == currentTip.HashBlock)
							yield break;
						foreach (var header in headers.Headers)
						{
							var h = header.GetHash();
							if (h == currentTip.HashBlock)
								continue;

							//The previous headers request timeout, this can arrive in case of big reorg
							if (header.HashPrevBlock != currentTip.HashBlock)
							{
								int reorgDepth = 0;
								var tempCurrentTip = currentTip;
								while (reorgDepth != acceptMaxReorgDepth && tempCurrentTip != null && header.HashPrevBlock != tempCurrentTip.HashBlock)
								{
									reorgDepth++;
									tempCurrentTip = tempCurrentTip.Previous;
								}
								if (reorgDepth != acceptMaxReorgDepth && tempCurrentTip != null)
									currentTip = tempCurrentTip;
							}

							if (header.HashPrevBlock == currentTip.HashBlock)
							{
								isOurs = true;
								currentTip = new ChainedBlock(header, h, currentTip);
								yield return currentTip;
								if (currentTip.HashBlock == hashStop)
									yield break;
							}
							else
								break; //Not our headers, continue receive
						}
						if (isOurs)
							break;  //Go ask for next header
					}
				}
			}
		}

		/// <summary>
		/// Synchronize a given Chain to the tip of this node if its height is higher. (Thread safe)
		/// </summary>
		/// <param name="chain">The chain to synchronize</param>
		/// <param name="hashStop">The location until which it synchronize</param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public IEnumerable<ChainedBlock> SynchronizeChain(ChainBase chain, uint256 hashStop = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			var oldTip = chain.Tip;

			var headers = GetHeadersFromFork(oldTip, hashStop, cancellationToken).ToList();
			if (headers.Count == 0)
				return new ChainedBlock[0];

			var newTip = headers[headers.Count - 1];

			if (newTip.Height <= oldTip.Height)
				throw new ProtocolException("No tip should have been recieved older than the local one");

			foreach (var header in headers)
			{
				if (!header.Validate(Network))
					throw new ProtocolException("An header which does not pass proof of work verification has been received");
			}

			chain.SetTip(newTip);

			return headers;
		}

		public IEnumerable<Block> GetBlocks(uint256 hashStop = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			var genesis = new ChainedBlock(Network.GetGenesis().Header, 0);
			return GetBlocksFromFork(genesis, hashStop, cancellationToken);
		}

		public IEnumerable<Block> GetBlocksFromFork(ChainedBlock currentTip, uint256 hashStop = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			using (var listener = CreateListener())
			{
				SendMessageAsync(new GetBlocksPayload()
				{
					BlockLocators = currentTip.GetLocator(),
				});

				var headers = GetHeadersFromFork(currentTip, hashStop, cancellationToken);

				foreach (var block in GetBlocks(headers.Select(b => b.HashBlock), cancellationToken))
				{
					yield return block;
				}
			}
		}

		public IEnumerable<Block> GetBlocks(IEnumerable<ChainedBlock> blocks, CancellationToken cancellationToken = default(CancellationToken))
		{
			return GetBlocks(blocks.Select(c => c.HashBlock), cancellationToken);
		}

		public IEnumerable<Block> GetBlocks(IEnumerable<uint256> neededBlocks, CancellationToken cancellationToken = default(CancellationToken))
		{
			AssertState(NodeState.HandShaked, cancellationToken);

			int simultaneous = 70;
			using (var listener = CreateListener()
								.OfType<BlockPayload>())
			{
				foreach (var invs in neededBlocks
									.Select(b => new InventoryVector()
									{
										Type = AddSupportedOptions(InventoryType.MSG_BLOCK),
										Hash = b
									})
									.Partition(() => simultaneous))
				{

					var remaining = new Queue<uint256>(invs.Select(k => k.Hash));
					SendMessageAsync(new GetDataPayload(invs.ToArray()));

					int maxQueued = 0;
					while (remaining.Count != 0)
					{
						var block = listener.ReceivePayload<BlockPayload>(cancellationToken).Object;
						maxQueued = Math.Max(listener.MessageQueue.Count, maxQueued);
						if (remaining.Peek() == block.GetHash())
						{
							remaining.Dequeue();
							yield return block;
						}
					}
					if (maxQueued < 10)
						simultaneous *= 2;
					else
						simultaneous /= 2;
					simultaneous = Math.Max(10, simultaneous);
					simultaneous = Math.Min(10000, simultaneous);
				}
			}
		}

		/// <summary>
		/// Create a listener that will queue messages until diposed
		/// </summary>
		/// <returns>The listener</returns>
		/// <exception cref="System.InvalidOperationException">Thrown if used on the listener's thread, as it would result in a deadlock</exception>
		public NodeListener CreateListener()
		{
			AssertNoListeningThread();
			return new NodeListener(this);
		}

		private void AssertState(NodeState nodeState, CancellationToken cancellationToken = default(CancellationToken))
		{
			if (nodeState == NodeState.HandShaked && State == NodeState.Connected)
				this.VersionHandshake(cancellationToken);
			if (nodeState != State)
				throw new InvalidOperationException("Invalid Node state, needed=" + nodeState + ", current= " + State);
		}

		public uint256[] GetMempool(CancellationToken cancellationToken = default(CancellationToken))
		{
			AssertState(NodeState.HandShaked);
			using (var listener = CreateListener().OfType<InvPayload>())
			{
				this.SendMessageAsync(new MempoolPayload());
				var invs = listener.ReceivePayload<InvPayload>(cancellationToken).Inventory.Select(i => i.Hash).ToList();
				var result = invs;
				while (invs.Count == InvPayload.MAX_INV_SZ)
				{
					invs = listener.ReceivePayload<InvPayload>(cancellationToken).Inventory.Select(i => i.Hash).ToList();
					result.AddRange(invs);
				}
				return result.ToArray();
			}
		}

		/// <summary>
		/// Retrieve transactions from the mempool
		/// </summary>
		/// <param name="cancellationToken">Cancellation token</param>
		/// <returns>Transactions in the mempool</returns>
		public Transaction[] GetMempoolTransactions(CancellationToken cancellationToken = default(CancellationToken))
		{
			return GetMempoolTransactions(GetMempool(), cancellationToken);
		}

		/// <summary>
		/// Retrieve transactions from the mempool by ids
		/// </summary>
		/// <param name="txIds">Transaction ids to retrieve</param>
		/// <param name="cancellationToken">Cancellation token</param>
		/// <returns>The transactions, if a transaction is not found, then it is not returned in the array.</returns>
		public Transaction[] GetMempoolTransactions(uint256[] txIds, CancellationToken cancellationToken = default(CancellationToken))
		{
			AssertState(NodeState.HandShaked);
			if (txIds.Length == 0)
				return new Transaction[0];
			List<Transaction> result = new List<Transaction>();
			using (var listener = CreateListener().Where(m => m.Message.Payload is TxPayload || m.Message.Payload is NotFoundPayload))
			{
				foreach (var batch in txIds.Partition(500))
				{
					this.SendMessageAsync(new GetDataPayload(batch.Select(txid => new InventoryVector()
					{
						Type = AddSupportedOptions(InventoryType.MSG_TX),
						Hash = txid
					}).ToArray()));
					try
					{
						List<Transaction> batchResult = new List<NBitcoin.Transaction>();
						while (batchResult.Count < batch.Count)
						{
							CancellationTokenSource timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10.0));
							var payload = listener.ReceivePayload<Payload>(CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token).Token);
							if (payload is NotFoundPayload)
								batchResult.Add(null);
							else
								batchResult.Add(((TxPayload)payload).Object);
						}
						result.AddRange(batchResult);
					}
					catch (OperationCanceledException)
					{
						if (cancellationToken.IsCancellationRequested)
						{
							throw;
						}
					}
				}
			}

			return result.Where(r => r != null).ToArray();
		}

		/// <summary>
		/// Add supported option to the input inventory type
		/// </summary>
		/// <param name="inventoryType">Inventory type (like MSG_TX)</param>
		/// <returns>Inventory type with options (MSG_TX | MSG_WITNESS_FLAG)</returns>
		public InventoryType AddSupportedOptions(InventoryType inventoryType)
		{
			if ((actualTransactionOptions & TransactionOptions.Witness) != 0)
				inventoryType |= InventoryType.MSG_WITNESS_FLAG;
			return inventoryType;
		}

		/// <summary>
		/// Emit a ping and wait the pong
		/// </summary>
		/// <param name="cancellation"></param>
		/// <returns>Latency</returns>
		public TimeSpan PingPong(CancellationToken cancellation = default(CancellationToken))
		{
			using (var listener = CreateListener().OfType<PongPayload>())
			{
				var ping = new PingPayload()
				{
					Nonce = RandomUtils.GetUInt64()
				};
				var before = DateTimeOffset.UtcNow;
				SendMessageAsync(ping);

				while (listener.ReceivePayload<PongPayload>(cancellation).Nonce != ping.Nonce)
				{
				}
				var after = DateTimeOffset.UtcNow;
				return after - before;
			}
		}

		#region IDisposable Members

		public void Dispose()
		{
			Disconnect("Node disposed");
		}

		#endregion

		#region System Members

		public override string ToString()
		{
			return String.Format("{0} ({1})", State, Peer.Endpoint);
		}

		#endregion
	}

	internal class NodeConnection
	{
		private readonly CancellationTokenSource cancel;
		public CancellationTokenSource Cancel
		{
			get { return cancel; }
		}

		private readonly ManualResetEvent disconnected;
		public ManualResetEvent Disconnected
		{
			get { return disconnected; }
		}

		private readonly Node node;
		public Node Node
		{
			get { return node; }
		}

		readonly Socket socket;
		public Socket Socket
		{
			get { return socket; }
		}

		internal BlockingCollection<SentMessage> Messages = new BlockingCollection<SentMessage>(new ConcurrentQueue<SentMessage>());

#if NOTRACESOURCE
			internal
#else
		public
#endif
 TraceCorrelation TraceCorrelation
		{
			get
			{
				return Node.TraceCorrelation;
			}
		}

		public NodeConnection(Node node, Socket socket)
		{
			this.node = node;
			this.socket = socket;
			disconnected = new ManualResetEvent(false);
			cancel = new CancellationTokenSource();
		}

		public void BeginListen()
		{
			new Thread(() =>
			{
				SentMessage processing = null;
				Exception unhandledException = null;
				bool isVerbose = NodeServerTrace.Trace.Switch.ShouldTrace(TraceEventType.Verbose);
				ManualResetEvent ar = new ManualResetEvent(false);
				SocketAsyncEventArgs evt = new SocketAsyncEventArgs();
				evt.SocketFlags = SocketFlags.None;
				evt.Completed += (a, b) =>
				{
					Utils.SafeSet(ar);
				};
				try

				{
					foreach (var kv in Messages.GetConsumingEnumerable(Cancel.Token))
					{
						processing = kv;
						var payload = kv.Payload;
						var message = new Message();
						message.Magic = node.Network.Magic;
						message.Payload = payload;

						if (isVerbose)
						{
							// NETSTDCONV Trace.CorrelationManager.ActivityId = kv.ActivityId;
							if (kv.ActivityId != TraceCorrelation.Activity)
							{
								NodeServerTrace.Transfer(TraceCorrelation.Activity);
								// NETSTDCONV Trace.CorrelationManager.ActivityId = TraceCorrelation.Activity;
							}
							NodeServerTrace.Verbose("Sending message " + message);
						}

						MemoryStream ms = new MemoryStream();
						message.ReadWrite(new BitcoinStream(ms, true)
						{
							ProtocolVersion = Node.Version,
							TransactionOptions = Node.SupportedTransactionOptions
						});
						var bytes = ms.ToArrayEfficient();
						evt.SetBuffer(bytes, 0, bytes.Length);
						node.Counter.AddWritten(bytes.Length);
						ar.Reset();
						if (!Socket.SendAsync(evt))
							Utils.SafeSet(ar);
						WaitHandle.WaitAny(new WaitHandle[] { ar, Cancel.Token.WaitHandle }, -1);
						if (!Cancel.Token.IsCancellationRequested)
						{
							if (evt.SocketError != SocketError.Success)
								throw new SocketException((int)evt.SocketError);
							processing.Completion.SetResult(true);
							processing = null;
						}
					}
				}
				catch (OperationCanceledException)
				{
				}
				catch (Exception ex)
				{
					unhandledException = ex;
				}
				finally
				{
					evt.Dispose();
					ar.Dispose();
				}

				if (processing != null)
					Messages.Add(processing);

				foreach (var pending in Messages)
				{
					if (isVerbose)
					{
						// NETSTDCONV Trace.CorrelationManager.ActivityId = pending.ActivityId;
						if (pending != processing && pending.ActivityId != TraceCorrelation.Activity)
							NodeServerTrace.Transfer(TraceCorrelation.Activity);
						// NETSTDCONV Trace.CorrelationManager.ActivityId = TraceCorrelation.Activity;
						NodeServerTrace.Verbose("The connection cancelled before the message was sent");
					}
					pending.Completion.SetException(new OperationCanceledException("The peer has been disconnected"));
				}
				Messages = new BlockingCollection<SentMessage>(new ConcurrentQueue<SentMessage>());
				NodeServerTrace.Information("Stop sending");
				Cleanup(unhandledException);
			}).Start();
			new Thread(() =>
			{
				_ListenerThreadId = Thread.CurrentThread.ManagedThreadId;
				using (TraceCorrelation.Open(false))
				{
					NodeServerTrace.Information("Listening");
					Exception unhandledException = null;
					byte[] buffer = node.ReuseBuffer ? new byte[1024 * 1024] : null;
					try
					{
						var stream = new NetworkStream(Socket, false);
						while (!Cancel.Token.IsCancellationRequested)
						{
							PerformanceCounter counter;

							var message = Message.ReadNext(stream, Node.Network, Node.Version, Cancel.Token, buffer, out counter);
							if (NodeServerTrace.Trace.Switch.ShouldTrace(TraceEventType.Verbose))
								NodeServerTrace.Verbose("Receiving message : " + message.Command + " (" + message.Payload + ")");
							Node.LastSeen = DateTimeOffset.UtcNow;
							Node.Counter.Add(counter);
							Node.OnMessageReceived(new IncomingMessage()
							{
								Message = message,
								Socket = Socket,
								Length = counter.ReadenBytes,
								Node = Node
							});
						}
					}
					catch (OperationCanceledException)
					{
					}
					catch (Exception ex)
					{
						unhandledException = ex;
					}
					NodeServerTrace.Information("Stop listening");
					Cleanup(unhandledException);
				}
			}).Start();
		}

		int _CleaningUp;
		public int _ListenerThreadId;
		private void Cleanup(Exception unhandledException)
		{
			if (Interlocked.CompareExchange(ref _CleaningUp, 1, 0) == 1)
				return;

			if (!Cancel.IsCancellationRequested)
			{
				NodeServerTrace.Error("Connection to server stopped unexpectedly", unhandledException);

				Node.DisconnectReason = new NodeDisconnectReason()
				{
					Reason = "Unexpected exception while connecting to socket",
					Exception = unhandledException
				};

				Node.State = NodeState.Failed;
			}

			if (Node.State != NodeState.Failed)
				Node.State = NodeState.Offline;

			cancel.Cancel();
			Utils.SafeCloseSocket(Socket);
			disconnected.Set(); //Set before behavior detach to prevent deadlock

			foreach (var behavior in node.Behaviors)
			{
				try
				{
					behavior.Detach();
				}
				catch (Exception ex)
				{
					NodeServerTrace.Error("Error while detaching behavior " + behavior.GetType().FullName, ex);
				}
			}
		}
	}

	public sealed class NodeDisconnectReason
	{
		public Exception Exception { get; set; }
		public string Reason { get; set; }
	}

	public sealed class NodeRequirement
	{
		public ProtocolVersion? MinVersion { get; set; }
		public NodeServices RequiredServices { get; set; }
		public bool SupportSPV { get; set; }

		public bool Check(VersionPayload version)
		{
			if (MinVersion != null)
			{
				if (version.Version < MinVersion.Value)
					return false;
			}

			if ((RequiredServices & version.Services) != RequiredServices)
			{
				return false;
			}

			if (SupportSPV)
			{
				if (version.Version < ProtocolVersion.MEMPOOL_GD_VERSION)
					return false;
				if (ProtocolVersion.NO_BLOOM_VERSION <= version.Version && ((version.Services & NodeServices.NODE_BLOOM) == 0))

					return false;
			}
			return true;
		}
	}

	public enum NodeState : int
	{
		Failed,
		Offline,
		Disconnecting,
		Connected,
		HandShaked
	}

	internal sealed class SentMessage
	{
		public Payload Payload;
		public TaskCompletionSource<bool> Completion;
		public Guid ActivityId;
	}
}

#endif