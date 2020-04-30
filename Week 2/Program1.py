import networkx as nx
# Имеющимися методами библиотеки инициализируем граф
g = nx.Graph([[84, 71], [68, 28], [81, 80], [55, 25], [44, 39], [74, 75], [73, 20], [25, 18], [5, 50], [59, 91], [54, 67], [91, 29], [31, 83], [2, 83], [87, 78], [84, 97], [42, 21], [92, 85], [1, 53], [90, 22], [63, 14], [60, 23], [10, 96], [16, 40], [70, 41], [0, 16], [11, 65], [46, 36], [30, 42], [64, 32], [26, 84], [93, 51], [71, 87], [34, 19], [64, 61], [37, 16], [8, 82], [34, 3], [85, 50], [13, 69], [58, 56], [99, 8], [53, 98], [17, 12], [7, 38], [15, 42], [60, 81], [79, 48], [35, 47], [17, 4], [43, 49], [52, 86], [18, 11], [43, 9], [32, 88], [77, 45], [74, 11], [81, 51], [6, 1], [30, 29], [72, 82], [52, 58], [62, 7], [47, 97], [79, 94], [73, 58], [63, 46], [79, 68], [7, 67], [12, 24], [27, 33], [89, 45], [41, 9], [5, 88], [25, 10], [95, 39], [39, 8], [63, 24], [79, 63], [47, 25], [98, 45], [83, 73], [70, 37], [96, 8], [63, 87], [99, 31], [59, 67], [57, 66], [81, 34], [30, 90], [27, 13], [89, 66], [76, 54], [35, 51], [54, 28], [82, 32], [13, 43], [89, 15], [41, 19]])
maximum = 0 # наш диаметр сети - максимальный по длине путь от некоторой i-ой вершины к j-ой
pp = nx.shortest_path_length(g) # pp - словарик, в котором ключ - стартовая вершина, а значение - словарь, в котором ключ - конечная вершина, а значение - кратчайшее расстояние в пройденных вершинах
# учтем, что данный метод реализован так: def shortest_path_length(G, source=None, target=None, weight=None, method='dijkstra'): то есть, по-умолчанию применяется алгоритм Дейкстры.
#Сложность алгоритма Дейкстры зависит от способа нахождения вершины v, а также способа хранения множества непосещённых вершин и способа обновления меток. 
#Обозначим через n количество вершин, а через m — количество рёбер в графе G.
#В простейшем случае, когда для поиска вершины с минимальным d[v] просматривается всё множество вершин, а для хранения величин d используется массив,
# время работы алгоритма есть O(n^{2}). Основной цикл выполняется порядка n раз, в каждом из них на нахождение минимума тратится порядка n операций. 
#На циклы по соседям каждой посещаемой вершины тратится количество операций, пропорциональное количеству рёбер m 
#(поскольку каждое ребро встречается в этих циклах ровно дважды и требует константное число операций). 
#Таким образом, общее время работы алгоритма  O(n^{2}+m), но, так как m <= n(n-1) , оно составляет O(n^{2}).
for i in range(len(nx.nodes(g))): # в словарике для каждой вершины записано минимальное число ребер, по которым надо пройти, чтобы достигнуть каждой вершины, с которой возможна связь
	for j in range(len(nx.nodes(g))): # в итоге чтобы узнать кратчайшее расстояние от вершины i до вершины j, достаточно лишь p[i][j]
		if pp[i][j] > maximum: # максимальное значение среди всех этих расстояний - диаметр сети
			maximum = pp[i][j]
print(maximum)